// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {IBurnRootVerifier} from "./IBurnRootVerifier.sol";

/// @title BridgeVault — RFP-022 Ethereum escrow for one LEZ bridge configuration
/// @notice Deposits fixed denominations of ERC-20s or native ETH (`token == address(0)`) against a commitment
///         `C`; releases them on a Groth16 proof that a burn commitment is in an accepted LEZ burn root.
///         Burn roots are accepted through `ROOT_VERIFIER`, which in the prototype is `EcdsaRootVerifier`:
///         INTERIM, CUSTODIAL, NOT TRUSTLESS (docs/ARCHITECTURE.md §3.1, §3.6). Every verification address, the image id, the
///         config id and the fee bound are immutable (no setter).
contract BridgeVault is Ownable2Step, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    bytes32 public constant TAG_REL = bytes32("b022/rel/v1");
    /// `acceptedAt` sentinel of a revoked root: permanently invalid, never re-acceptable.
    uint256 public constant REVOKED = type(uint256).max;

    IBurnRootVerifier public immutable ROOT_VERIFIER;
    IRiscZeroVerifier public immutable GROTH16;
    bytes32 public immutable MEMBERSHIP_IMAGE_ID;
    bytes32 public immutable CONFIG_ID;
    uint256 public immutable MAX_FEE_BPS;
    /// Pauses each half (globally or per token), revokes roots and cancels queued token changes. Fixed and
    /// distinct from the admin at construction (the admin cannot become the freezer).
    address public immutable FREEZER;
    /// Floor on the queue time of a loosening token change, whatever the token's current `releaseDelay`.
    uint256 public immutable MIN_TIMELOCK;
    /// Ceiling on any `releaseDelay` (a tightening applies at once, so it needs a bound: an unbounded delay would
    /// lock the escrow). Every queue lock is then at most max(MAX_DELAY, MIN_TIMELOCK) <= 30 days.
    uint256 public constant MAX_DELAY = 7 days;

    struct TokenConfig {
        bool listed; // deposits need it; releases of a delisted token stay possible
        bool depositsOpen;
        uint64 releaseDelay; // seconds after root acceptance (inclusive)
        uint64 window; // fixed cap window W in seconds, > 0
        uint128 depositCap; // per window, token base units
        uint128 releaseCap; // per window, token base units
    }

    struct Denom {
        bool permitted;
        uint128 standardFee; // published relayer fee; the payout uses the proven fee only
    }

    /// Last applied config. A queued change that has matured is NOT reflected here until the next `setToken`:
    /// monitors and clients must read the config in force with `effectiveToken`.
    mapping(address => TokenConfig) public tokens;
    mapping(address => TokenConfig) public pendingToken;
    mapping(address => uint256) public pendingTokenAt;
    mapping(address => mapping(uint256 => Denom)) public denoms;
    /// Last applied depth; read the one in force with `effectiveMinLezDepth` (a queued decrease may have matured).
    uint64 public minLezDepth;
    uint64 public pendingMinLezDepth;
    uint256 public pendingMinLezDepthAt;

    bool public depositsFrozen;
    bool public releasesFrozen;
    mapping(address => bool) public tokenDepositsFrozen;
    mapping(address => bool) public tokenReleasesFrozen;

    mapping(bytes32 => bool) public seen; // deposit commitments
    mapping(bytes32 => bool) public spent; // release nullifiers Nb
    mapping(address => mapping(uint256 => mapping(bytes32 => uint256))) public acceptedAt;
    mapping(address => mapping(uint256 => uint256)) public depositUsed; // [token][window index]
    mapping(address => mapping(uint256 => uint256)) public releaseUsed;

    event Deposit(bytes32 indexed commitment, address indexed token, bytes32 indexed configId, uint256 amount);
    event BurnRootAccepted(
        address indexed token,
        uint256 indexed denom,
        bytes32 indexed burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash
    );
    event BurnRootRevoked(address indexed token, uint256 indexed denom, bytes32 indexed burnRoot);
    event TokenChangeQueued(address indexed token, uint256 activeAt);
    event TokenChangeCancelled(address indexed token);
    event MinLezDepthChangeQueued(uint64 depth, uint256 activeAt);

    error NotFreezer();
    error BadParam();
    error TokenNotListed();
    error DepositsClosed();
    error DenomNotPermitted();
    error Frozen();
    error CommitmentSeen();
    error BadValue();
    error AmountMismatch(uint256 received);
    error CapExceeded();
    error RootAlreadyAccepted();
    error RootNotAccepted();
    error RootRevoked();
    error ReleaseTooEarly();
    error FeeTooHigh();
    error NullifierSpent();

    modifier onlyFreezer() {
        if (msg.sender != FREEZER) revert NotFreezer();
        _;
    }

    constructor(
        address admin,
        address freezer,
        IBurnRootVerifier rootVerifier,
        IRiscZeroVerifier groth16,
        bytes32 membershipImageId,
        bytes32 configId,
        uint256 maxFeeBps,
        uint256 minTimelock
    ) Ownable(admin) {
        if (
            freezer == address(0) || freezer == admin || maxFeeBps > 10_000 || minTimelock < 10 minutes
                || minTimelock > 30 days
        ) {
            revert BadParam();
        }
        FREEZER = freezer;
        MIN_TIMELOCK = minTimelock;
        ROOT_VERIFIER = rootVerifier;
        GROTH16 = groth16;
        MEMBERSHIP_IMAGE_ID = membershipImageId;
        CONFIG_ID = configId;
        MAX_FEE_BPS = maxFeeBps;
    }

    // ── admin ──────────────────────────────────────────────────────────────────────────────────────────

    /// First listing applies at once and fixes `window` for good. Later, `listed`/`depositsOpen` apply at once,
    /// and so does a tightening (delay not lower, no cap higher), which also drops any queued change. A
    /// loosening is queued for max(current `releaseDelay`, `MIN_TIMELOCK`) (`pendingTokenAt`) and the freezer
    /// can cancel it, so a compromised admin cannot shorten the delay or lift a cap faster than the freezer
    /// can react — provided the freezer watches `TokenChangeQueued`.
    function setToken(address token, TokenConfig calldata c) external onlyOwner {
        if (c.window == 0 || c.releaseDelay > MAX_DELAY) revert BadParam();
        TokenConfig memory cur = effectiveToken(token);
        if (cur.window == 0) {
            tokens[token] = c;
            return;
        }
        if (c.window != cur.window) revert BadParam(); // a new window would reset the cap counters
        delete pendingTokenAt[token];
        if (c.releaseDelay >= cur.releaseDelay && c.depositCap <= cur.depositCap && c.releaseCap <= cur.releaseCap) {
            tokens[token] = c;
            return;
        }
        (cur.listed, cur.depositsOpen) = (c.listed, c.depositsOpen);
        tokens[token] = cur;
        pendingToken[token] = c;
        uint256 lock = cur.releaseDelay > MIN_TIMELOCK ? cur.releaseDelay : MIN_TIMELOCK;
        pendingTokenAt[token] = block.timestamp + lock;
        emit TokenChangeQueued(token, pendingTokenAt[token]);
    }

    /// The config in force now: `tokens` with a matured queued change applied.
    function effectiveToken(address token) public view returns (TokenConfig memory c) {
        c = tokens[token];
        uint256 at = pendingTokenAt[token];
        if (at != 0 && block.timestamp >= at) {
            TokenConfig memory p = pendingToken[token];
            (c.releaseDelay, c.window, c.depositCap, c.releaseCap) =
            (p.releaseDelay, p.window, p.depositCap, p.releaseCap);
        }
    }

    function setDenom(address token, uint256 denom, bool permitted, uint128 standardFee) external onlyOwner {
        if (denom == 0 || uint256(standardFee) * 10_000 > denom * MAX_FEE_BPS) revert BadParam();
        denoms[token][denom] = Denom(permitted, standardFee);
    }

    /// Read by the root signers (`effectiveMinLezDepth`); accepted roots are unaffected by a change. An increase
    /// applies at once and drops a queued decrease; a decrease is queued for `MIN_TIMELOCK`.
    function setMinLezDepth(uint64 depth) external onlyOwner {
        uint64 cur = effectiveMinLezDepth();
        minLezDepth = cur;
        delete pendingMinLezDepthAt;
        if (depth >= cur) {
            minLezDepth = depth;
            return;
        }
        pendingMinLezDepth = depth;
        pendingMinLezDepthAt = block.timestamp + MIN_TIMELOCK;
        emit MinLezDepthChangeQueued(depth, pendingMinLezDepthAt);
    }

    function effectiveMinLezDepth() public view returns (uint64) {
        uint256 at = pendingMinLezDepthAt;
        return at != 0 && block.timestamp >= at ? pendingMinLezDepth : minLezDepth;
    }

    // ── freezer ────────────────────────────────────────────────────────────────────────────────────────

    function setFrozen(bool deposits, bool releases) external onlyFreezer {
        depositsFrozen = deposits;
        releasesFrozen = releases;
    }

    function setTokenFrozen(address token, bool deposits, bool releases) external onlyFreezer {
        tokenDepositsFrozen[token] = deposits;
        tokenReleasesFrozen[token] = releases;
    }

    /// Drops a queued, not yet matured `setToken` loosening.
    function cancelTokenChange(address token) external onlyFreezer {
        uint256 at = pendingTokenAt[token];
        if (at == 0 || block.timestamp >= at) revert BadParam();
        delete pendingTokenAt[token];
        emit TokenChangeCancelled(token);
    }

    /// Permanent, also after the delay has matured; releases already made stay made.
    function revokeRoot(address token, uint256 denom, bytes32 burnRoot) external onlyFreezer {
        acceptedAt[token][denom][burnRoot] = REVOKED;
        emit BurnRootRevoked(token, denom, burnRoot);
    }

    // ── deposit ────────────────────────────────────────────────────────────────────────────────────────

    function deposit(address token, uint256 denom, bytes32 commitment) external payable nonReentrant {
        TokenConfig memory c = effectiveToken(token);
        if (!c.listed) revert TokenNotListed();
        if (!c.depositsOpen) revert DepositsClosed();
        if (!denoms[token][denom].permitted) revert DenomNotPermitted();
        if (depositsFrozen || tokenDepositsFrozen[token]) revert Frozen();
        if (seen[commitment]) revert CommitmentSeen();
        seen[commitment] = true;
        _useCap(depositUsed[token], c.window, c.depositCap, denom);

        if (token == address(0)) {
            if (msg.value != denom) revert BadValue();
        } else {
            if (msg.value != 0) revert BadValue();
            uint256 before = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), denom);
            uint256 received = IERC20(token).balanceOf(address(this)) - before;
            if (received != denom) revert AmountMismatch(received);
        }
        emit Deposit(commitment, token, CONFIG_ID, denom);
    }

    // ── burn roots (INTERIM, CUSTODIAL) ───────────────────────────────────────────────────────────────

    /// Accepts each root once; a replayed attestation cannot reset the delay. No monotonic `count` rule.
    function acceptBurnRoot(
        address token,
        uint256 denom,
        bytes32 burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash,
        bytes calldata attestation
    ) external {
        if (acceptedAt[token][denom][burnRoot] != 0) revert RootAlreadyAccepted();
        ROOT_VERIFIER.verifyRoot(token, denom, burnRoot, count, lezHeight, lezBlockHash, attestation);
        acceptedAt[token][denom][burnRoot] = block.timestamp;
        emit BurnRootAccepted(token, denom, burnRoot, count, lezHeight, lezBlockHash);
    }

    // ── release ────────────────────────────────────────────────────────────────────────────────────────

    /// The `burn_member` journal this vault verifies: 11 static words, 352 bytes.
    function releaseJournal(
        address token,
        uint256 denom,
        bytes32 burnRoot,
        bytes32 nb,
        address recipient,
        address relayer,
        uint256 fee
    ) public view returns (bytes memory) {
        return abi.encode(
            TAG_REL, block.chainid, address(this), CONFIG_ID, token, denom, burnRoot, nb, recipient, relayer, fee
        );
    }

    /// Pays `denom - fee` to `recipient` and `fee` to `relayer`; both are bound in the proof.
    function release(
        address token,
        uint256 denom,
        bytes32 burnRoot,
        bytes32 nb,
        address recipient,
        address relayer,
        uint256 fee,
        bytes calldata seal
    ) external nonReentrant {
        _checkRelease(token, denom, burnRoot, fee);
        if (spent[nb]) revert NullifierSpent();
        spent[nb] = true;

        GROTH16.verify(
            seal, MEMBERSHIP_IMAGE_ID, sha256(releaseJournal(token, denom, burnRoot, nb, recipient, relayer, fee))
        );

        if (token == address(0)) {
            Address.sendValue(payable(recipient), denom - fee);
            if (fee != 0) Address.sendValue(payable(relayer), fee);
        } else {
            IERC20(token).safeTransfer(recipient, denom - fee);
            if (fee != 0) IERC20(token).safeTransfer(relayer, fee);
        }
    }

    function _checkRelease(address token, uint256 denom, bytes32 burnRoot, uint256 fee) private {
        uint256 at = acceptedAt[token][denom][burnRoot];
        if (at == 0) revert RootNotAccepted();
        if (at == REVOKED) revert RootRevoked();
        TokenConfig memory c = effectiveToken(token);
        if (block.timestamp < at + c.releaseDelay) revert ReleaseTooEarly();
        if (releasesFrozen || tokenReleasesFrozen[token]) revert Frozen();
        if (fee * 10_000 > denom * MAX_FEE_BPS) revert FeeTooHigh();
        _useCap(releaseUsed[token], c.window, c.releaseCap, denom);
    }

    /// Fixed window `[wW, (w+1)W)`: a timestamp on a boundary counts in the new window.
    function _useCap(mapping(uint256 => uint256) storage used, uint64 window, uint128 cap, uint256 amount) private {
        uint256 w = block.timestamp / window;
        uint256 u = used[w] + amount;
        if (u > cap) revert CapExceeded();
        used[w] = u;
    }
}
