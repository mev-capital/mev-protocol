//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import '@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol';
import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import '@openzeppelin/contracts/security/Pausable.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';
import './interfaces/IStrategy.sol';

/**
 *
 * @title MevProtocol Protocol
 *
 * @notice Contract for Curve&Convex&Frax&Uniswap protocols optimize.
 * Users can use this contract for optimize yield and gas.
 *
 *
 * @dev MevProtocol is main contract.
 * Contract does not store user funds.
 * All user funds goes to Convex&Curve pools.
 *
 */

contract MevProtocol is ERC20, Pausable, AccessControl {
    using SafeERC20 for IERC20Metadata;

    bytes32 public constant OPERATOR_ROLE = keccak256('OPERATOR_ROLE');
    uint8 public constant POOL_ASSETS = 3;
    uint256 public constant LP_RATIO_MULTIPLIER = 1e18;
    uint256 public constant FEE_DENOMINATOR = 1000;
    uint256 public constant MIN_LOCK_TIME = 1 days;
    uint256 public constant FUNDS_DENOMINATOR = 10_000;
    uint8 public constant ALL_WITHDRAWAL_TYPES_MASK = uint8(3); // Binary 11 = 2^0 + 2^1;

    struct PendingWithdrawal {
        uint256 lpShares;
        uint256[POOL_ASSETS] tokenAmounts;
        IStrategy.WithdrawalType withdrawalType;
        uint128 tokenIndex;
    }

    struct PoolInfo {
        IStrategy strategy;
        uint256 startTime;
        uint256 lpShares;
        bool enabled;
    }

    PoolInfo[] internal _poolInfo;

    uint256 public defaultDepositPid;
    uint256 public defaultWithdrawPid;

    uint8 public availableWithdrawalTypes;

    address[POOL_ASSETS] public tokens;
    uint256[POOL_ASSETS] public decimalsMultipliers;

    mapping(address => uint256[POOL_ASSETS]) internal _pendingDeposits;
    mapping(address => PendingWithdrawal) internal _pendingWithdrawals;

    uint256 public totalDeposited = 0;
    uint256 public managementFee = 100; // 10%
    bool public launched = false;

    event CreatedPendingDeposit(address indexed depositor, uint256[POOL_ASSETS] amounts);
    event CreatedPendingWithdrawal(
        address indexed withdrawer,
        uint256 lpShares,
        uint256[POOL_ASSETS] tokenAmounts
    );
    event RemovedPendingDeposit(address indexed depositor);
    event RemovedPendingWithdrawal(address indexed depositor);

    event Deposited(
        address indexed depositor,
        uint256 depositedValue,
        uint256[POOL_ASSETS] amounts,
        uint256 lpShares,
        bool optimized
    );

    event Withdrawn(
        address indexed withdrawer,
        uint256 lpShares,
        IStrategy.WithdrawalType withdrawalType,
        uint128 tokenIndex,
        bool optimized
    );
    event FailedWithdrawal(
        address indexed withdrawer,
        uint256[POOL_ASSETS] amounts,
        uint256 lpShares,
        IStrategy.WithdrawalType withdrawalType,
        uint128 tokenIndex
    );

    event AddedPool(uint256 pid, address strategyAddr, uint256 startTime);
    event SetDefaultDepositPid(uint256 pid);
    event SetDefaultWithdrawPid(uint256 pid);
    event ClaimedAllManagementFee(uint256 feeValue);
    event AutoCompoundAll(uint256 compoundedValue);
    event ToggledEnabledPoolStatus(address pool, bool newStatus);

    modifier startedPool() {
        require(_poolInfo.length != 0, 'MevProtocol: pools not existed!');
        require(
            block.timestamp >= _poolInfo[defaultDepositPid].startTime,
            'MevProtocol: default deposit pool not started yet!'
        );
        require(
            block.timestamp >= _poolInfo[defaultWithdrawPid].startTime,
            'MevProtocol: default withdraw pool not started yet!'
        );
        _;
    }

    modifier enabledPool(uint256 poolIndex) {
        require(_poolInfo[poolIndex].enabled, 'MevProtocol: operations with not enabled pool');
        _;
    }

    constructor(address[POOL_ASSETS] memory _tokens) ERC20('MevProtocolLP', 'MPLP') {
        tokens = _tokens;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(OPERATOR_ROLE, msg.sender);

        for (uint256 i; i < POOL_ASSETS; i++) {
            uint256 decimals = IERC20Metadata(tokens[i]).decimals();
            if (decimals < 18) {
                decimalsMultipliers[i] = 10**(18 - decimals);
            } else {
                decimalsMultipliers[i] = 1;
            }
        }

        availableWithdrawalTypes = ALL_WITHDRAWAL_TYPES_MASK;
    }

    function poolInfo(uint256 pid) external view returns (PoolInfo memory) {
        return _poolInfo[pid];
    }

    function pendingDeposits(address user) external view returns (uint256[POOL_ASSETS] memory) {
        return _pendingDeposits[user];
    }

    function pendingDepositsToken(address user, uint256 tokenIndex)
        external
        view
        returns (uint256)
    {
        return _pendingDeposits[user][tokenIndex];
    }

    function pendingWithdrawals(address user) external view returns (PendingWithdrawal memory) {
        return _pendingWithdrawals[user];
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setAvailableWithdrawalTypes(uint8 newAvailableWithdrawalTypes)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(
            newAvailableWithdrawalTypes <= ALL_WITHDRAWAL_TYPES_MASK,
            'MevProtocol: wrong available withdrawal types'
        );
        availableWithdrawalTypes = newAvailableWithdrawalTypes;
    }

    /**
     * @dev update managementFee, this is a MevProtocol commission from protocol profit
     * @param  newManagementFee - minAmount 0, maxAmount FEE_DENOMINATOR - 1
     */
    function setManagementFee(uint256 newManagementFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newManagementFee < FEE_DENOMINATOR, 'MevProtocol: wrong fee');
        managementFee = newManagementFee;
    }

    /**
     * @dev Returns managementFee for strategy's when contract sell rewards
     * @return Returns commission on the amount of profit in the transaction
     * @param amount - amount of profit for calculate managementFee
     */
    function calcManagementFee(uint256 amount) external view returns (uint256) {
        return (amount * managementFee) / FEE_DENOMINATOR;
    }

    /**
     * @dev Claims managementFee from all active strategies
     */
    function claimAllManagementFee() external {
        uint256 feeTotalValue;
        for (uint256 i = 0; i < _poolInfo.length; i++) {
            feeTotalValue += _poolInfo[i].strategy.claimManagementFees();
        }

        emit ClaimedAllManagementFee(feeTotalValue);
    }

    function autoCompoundAll() external {
        uint256 totalCompounded = 0;
        for (uint256 i = 0; i < _poolInfo.length; i++) {
            if (_poolInfo[i].lpShares > 0) {
                totalCompounded += _poolInfo[i].strategy.autoCompound();
            }
        }
        emit AutoCompoundAll(totalCompounded);
    }

    /**
     * @dev Returns total holdings for all pools (strategy's)
     * @return Returns sum holdings (USD) for all pools
     */
    function totalHoldings() public view returns (uint256) {
        uint256 length = _poolInfo.length;
        uint256 totalHold = 0;
        for (uint256 pid = 0; pid < length; pid++) {
            if (_poolInfo[pid].lpShares > 0) {
                totalHold += _poolInfo[pid].strategy.totalHoldings();
            }
        }
        return totalHold;
    }

    /**
     * @dev Returns price depends on the income of users
     * @return Returns currently price of MPLP (1e18 = 1$)
     */
    function lpPrice() public view returns (uint256) {
        return calcTokenPrice(totalHoldings(), totalSupply());
    }

    function calcTokenPrice(uint256 holdings, uint256 tokens) internal pure returns (uint256) {
        return (holdings * 1e18) / tokens;
    }

    /**
     * @dev Returns number of pools
     * @return number of pools
     */
    function poolCount() external view returns (uint256) {
        return _poolInfo.length;
    }

    /**
     * @dev in this func user sends funds to the contract and then waits for the completion
     * of the transaction for all users
     * @param amounts - array of deposit amounts by user
     */
    function delegateDeposit(uint256[POOL_ASSETS] memory amounts) external whenNotPaused {
        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] > 0) {
                IERC20Metadata(tokens[i]).safeTransferFrom(_msgSender(), address(this), amounts[i]);
                _pendingDeposits[_msgSender()][i] += amounts[i];
            }
        }

        emit CreatedPendingDeposit(_msgSender(), amounts);
    }

    /**
     * @dev deposit in one tx, without waiting complete by dev
     * @return Returns amount of lpShares minted for user
     * @param amounts - user send amounts of stablecoins to deposit
     */
    function deposit(uint256[POOL_ASSETS] memory amounts)
        external
        whenNotPaused
        startedPool
        returns (uint256)
    {
        IStrategy strategy = _poolInfo[defaultDepositPid].strategy;

        uint256 holdingsBefore = totalHoldings();

        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] > 0) {
                IERC20Metadata(tokens[i]).safeTransferFrom(
                    _msgSender(),
                    address(strategy),
                    amounts[i]
                );
            }
        }
        uint256 depositedValue = strategy.deposit(amounts);
        require(depositedValue > 0, 'MevProtocol: too low deposit!');

        return
            processSuccessfulDeposit(_msgSender(), depositedValue, amounts, holdingsBefore, false);
    }

    function processSuccessfulDeposit(
        address user,
        uint256 depositedValue,
        uint256[POOL_ASSETS] memory depositedTokens,
        uint256 holdingsBefore,
        bool optimized
    ) internal returns (uint256 lpShares) {
        if (totalSupply() == 0) {
            lpShares = depositedValue;
        } else {
            lpShares = (totalSupply() * depositedValue) / holdingsBefore;
        }

        _mint(user, lpShares);
        _poolInfo[defaultDepositPid].lpShares += lpShares;
        emit Deposited(user, depositedValue, depositedTokens, lpShares, optimized);
        totalDeposited += depositedValue;
    }

    /**
     * @dev MevProtocol protocol owner complete all active pending deposits of users
     * @param userList - dev send array of users from pending to complete
     */
    function completeDeposits(address[] memory userList)
        external
        onlyRole(OPERATOR_ROLE)
        startedPool
    {
        IStrategy strategy = _poolInfo[defaultDepositPid].strategy;
        uint256 holdingsBefore = totalHoldings();

        uint256 holdingsNew;
        uint256[POOL_ASSETS] memory totalAmounts;
        uint256[] memory holdingsPerUser = new uint256[](userList.length);
        for (uint256 i = 0; i < userList.length; i++) {
            holdingsNew = 0;
            for (uint256 x = 0; x < totalAmounts.length; x++) {
                uint256 userTokenDeposit = _pendingDeposits[userList[i]][x];
                totalAmounts[x] += userTokenDeposit;
                holdingsNew += userTokenDeposit * decimalsMultipliers[x];
            }
            holdingsPerUser[i] = holdingsNew;
        }

        uint256 holdingsTotal = 0;
        for (uint256 y = 0; y < POOL_ASSETS; y++) {
            uint256 tokenAmountTotal = totalAmounts[y];
            if (tokenAmountTotal > 0) {
                holdingsTotal += tokenAmountTotal * decimalsMultipliers[y];
                IERC20Metadata(tokens[y]).safeTransfer(address(strategy), tokenAmountTotal);
            }
        }
        uint256 depositedValue = strategy.deposit(totalAmounts);
        require(depositedValue > 0, 'MevProtocol: too low deposit!');

        uint256 holdingsCounted = 0;
        uint256 userDepositedValue = 0;
        for (uint256 z = 0; z < userList.length; z++) {
            address userAddr = userList[z];
            userDepositedValue = (depositedValue * holdingsPerUser[z]) / holdingsTotal;
            processSuccessfulDeposit(
                userAddr,
                userDepositedValue,
                _pendingDeposits[userAddr],
                holdingsBefore + holdingsCounted,
                true
            );
            holdingsCounted += userDepositedValue;
            delete _pendingDeposits[userAddr];
        }
    }

    /**
     * @dev in this func user sends pending withdraw to the contract and then waits
     * for the completion of the transaction for all users
     * @param  lpShares - amount of MPLP for withdraw
     * @param tokenAmounts - array of amounts stablecoins that user want minimum receive
     */
    function delegateWithdrawal(
        uint256 lpShares,
        uint256[POOL_ASSETS] memory tokenAmounts,
        IStrategy.WithdrawalType withdrawalType,
        uint128 tokenIndex
    ) external whenNotPaused {
        require(lpShares > 0, 'MevProtocol: lpAmount must be higher 0');

        PendingWithdrawal memory withdrawal;
        address userAddr = _msgSender();

        withdrawal.lpShares = lpShares;
        withdrawal.tokenAmounts = tokenAmounts;
        withdrawal.withdrawalType = withdrawalType;
        withdrawal.tokenIndex = tokenIndex;

        _pendingWithdrawals[userAddr] = withdrawal;

        emit CreatedPendingWithdrawal(userAddr, lpShares, tokenAmounts);
    }

    /**
     * @dev withdraw in one tx, without waiting complete by dev
     * @param lpShares - amount of MPLP for withdraw
     * @param tokenAmounts -  array of amounts stablecoins that user want minimum receive
     */
    function withdraw(
        uint256 lpShares,
        uint256[POOL_ASSETS] memory tokenAmounts,
        IStrategy.WithdrawalType withdrawalType,
        uint128 tokenIndex
    ) external whenNotPaused startedPool {
        require(
            checkBit(availableWithdrawalTypes, uint8(withdrawalType)),
            'MevProtocol: withdrawal type not available'
        );
        IStrategy strategy = _poolInfo[defaultWithdrawPid].strategy;
        address userAddr = _msgSender();

        require(balanceOf(userAddr) >= lpShares, 'MevProtocol: not enough LP balance');
        require(
            strategy.withdraw(
                userAddr,
                calcLpRatioSafe(lpShares, _poolInfo[defaultWithdrawPid].lpShares),
                tokenAmounts,
                withdrawalType,
                tokenIndex
            ),
            'MevProtocol: incorrect withdraw params'
        );

        uint256 userDeposit = (totalDeposited * lpShares) / totalSupply();

        processSuccessfulWithdrawal(
            userAddr,
            userDeposit,
            lpShares,
            withdrawalType,
            tokenIndex,
            false
        );
    }

    function processSuccessfulWithdrawal(
        address user,
        uint256 userDeposit,
        uint256 lpShares,
        IStrategy.WithdrawalType withdrawalType,
        uint128 tokenIndex,
        bool optimized
    ) internal {
        _burn(user, lpShares);
        _poolInfo[defaultWithdrawPid].lpShares -= lpShares;
        totalDeposited -= userDeposit;
        emit Withdrawn(user, lpShares, withdrawalType, tokenIndex, optimized);
    }

    function processSuccessfulOptimizedWithdrawal(
        address[] memory userList,
        uint256[POOL_ASSETS] memory lpSharesTotals,
        uint256[POOL_ASSETS] memory prevBalances
    ) internal {
        uint256[POOL_ASSETS] memory diffBalances;
        for (uint256 i = 0; i < POOL_ASSETS; i++) {
            diffBalances[i] = IERC20Metadata(tokens[i]).balanceOf(address(this)) - prevBalances[i];
        }

        for (uint256 i = 0; i < userList.length; i++) {
            address user = userList[i];
            PendingWithdrawal memory withdrawal = _pendingWithdrawals[user];

            uint256 userDeposit = (totalDeposited * withdrawal.lpShares) / totalSupply();

            processSuccessfulWithdrawal(
                user,
                userDeposit,
                withdrawal.lpShares,
                withdrawal.withdrawalType,
                withdrawal.tokenIndex,
                true
            );

            uint256 transferAmount;
            for (uint256 j = 0; j < POOL_ASSETS; j++) {
                if (lpSharesTotals[j] == 0) continue;
                transferAmount = (diffBalances[j] * withdrawal.lpShares) / lpSharesTotals[j];

                if (transferAmount == 0) continue;
                IERC20Metadata(tokens[j]).safeTransfer(user, transferAmount);
            }

            delete _pendingWithdrawals[user];
        }
    }

    function calcLpRatioSafe(uint256 outLpShares, uint256 strategyLpShares)
        internal
        pure
        returns (uint256 lpShareRatio)
    {
        lpShareRatio = (outLpShares * LP_RATIO_MULTIPLIER) / strategyLpShares;
        require(
            lpShareRatio > 0 && lpShareRatio <= LP_RATIO_MULTIPLIER,
            'MevProtocol: Wrong out lp Ratio'
        );
    }

    function completeWithdrawal(address user) external onlyRole(OPERATOR_ROLE) startedPool {
        require(address(user) != address(0), 'MevProtocol: zero user address');

        IStrategy strategy = _poolInfo[defaultWithdrawPid].strategy;

        PendingWithdrawal memory withdrawal = _pendingWithdrawals[user];

        if (balanceOf(user) < withdrawal.lpShares) {
            emit FailedWithdrawal(
                user,
                withdrawal.tokenAmounts,
                withdrawal.lpShares,
                withdrawal.withdrawalType,
                withdrawal.tokenIndex
            );
            delete _pendingWithdrawals[user];
            return;
        }

        if (
            !(
                strategy.withdraw(
                    user,
                    calcLpRatioSafe(withdrawal.lpShares, _poolInfo[defaultWithdrawPid].lpShares),
                    withdrawal.tokenAmounts,
                    withdrawal.withdrawalType,
                    withdrawal.tokenIndex
                )
            )
        ) {
            emit FailedWithdrawal(
                user,
                withdrawal.tokenAmounts,
                withdrawal.lpShares,
                withdrawal.withdrawalType,
                withdrawal.tokenIndex
            );
            delete _pendingWithdrawals[user];
            return;
        }

        uint256 userDeposit = (totalDeposited * withdrawal.lpShares) / totalSupply();
        processSuccessfulWithdrawal(
            user,
            userDeposit,
            withdrawal.lpShares,
            withdrawal.withdrawalType,
            withdrawal.tokenIndex,
            false
        );
        delete _pendingWithdrawals[user];
    }

    /**
     * @dev MevProtocol protocol owner complete all active pending withdrawals of users
     * @param userList - users owns pending withdraw to complete
     */
    function completeWithdrawalsBase(
        address[] memory userList,
        uint256[POOL_ASSETS] memory minAmountsTotal
    ) external onlyRole(OPERATOR_ROLE) startedPool {
        require(userList.length > 0, 'MevProtocol: there are no pending withdrawals requests');

        IStrategy strategy = _poolInfo[defaultWithdrawPid].strategy;

        uint256 lpSharesTotal;

        uint256 i;
        address user;
        PendingWithdrawal memory withdrawal;
        for (i = 0; i < userList.length; i++) {
            user = userList[i];

            withdrawal = getWithdrawalSafe(user, IStrategy.WithdrawalType.Base);
            if (withdrawal.lpShares == 0) continue;

            lpSharesTotal += withdrawal.lpShares;
        }

        require(
            lpSharesTotal <= _poolInfo[defaultWithdrawPid].lpShares,
            'MevProtocol: Insufficient pool LP shares'
        );

        uint256[POOL_ASSETS] memory prevBalances = calcPrevTokenBalances();

        if (
            !strategy.withdraw(
                address(this),
                calcLpRatioSafe(lpSharesTotal, _poolInfo[defaultWithdrawPid].lpShares),
                minAmountsTotal,
                IStrategy.WithdrawalType.Base,
                0
            )
        ) {
            removeAllFailedWithdrawals(userList);
            return;
        }

        processSuccessfulOptimizedWithdrawal(
            userList,
            [lpSharesTotal, lpSharesTotal, lpSharesTotal],
            prevBalances
        );
    }

    function getWithdrawalSafe(address user, IStrategy.WithdrawalType neededType)
        internal
        returns (PendingWithdrawal memory withdrawal)
    {
        withdrawal = _pendingWithdrawals[user];
        require(withdrawal.withdrawalType == neededType, 'MevProtocol: incorrect withdrawal type');

        if (balanceOf(user) < withdrawal.lpShares) {
            emit FailedWithdrawal(
                user,
                withdrawal.tokenAmounts,
                withdrawal.lpShares,
                withdrawal.withdrawalType,
                withdrawal.tokenIndex
            );
            delete _pendingWithdrawals[user];
            return PendingWithdrawal(0, [uint256(0), 0, 0], IStrategy.WithdrawalType.Base, 0);
        }
    }

    function calcPrevTokenBalances()
        internal
        view
        returns (uint256[POOL_ASSETS] memory prevBalances)
    {
        for (uint256 i = 0; i < POOL_ASSETS; i++) {
            prevBalances[i] = IERC20Metadata(tokens[i]).balanceOf(address(this));
        }
    }

    function removeAllFailedWithdrawals(address[] memory userList) internal {
        for (uint256 i = 0; i < userList.length; i++) {
            address user = userList[i];
            PendingWithdrawal memory withdrawal = _pendingWithdrawals[user];

            emit FailedWithdrawal(
                user,
                withdrawal.tokenAmounts,
                withdrawal.lpShares,
                withdrawal.withdrawalType,
                withdrawal.tokenIndex
            );
            delete _pendingWithdrawals[user];
        }
    }

    function completeWithdrawalsOneCoin(
        address[] memory userList,
        uint256[POOL_ASSETS] memory minAmountsTotal
    ) external onlyRole(OPERATOR_ROLE) startedPool {
        require(userList.length > 0, 'MevProtocol: there are no pending withdrawals requests');

        IStrategy strategy = _poolInfo[defaultWithdrawPid].strategy;

        uint256[POOL_ASSETS] memory lpSharesTotals;

        address user;
        PendingWithdrawal memory withdrawal;
        for (uint256 i = 0; i < userList.length; i++) {
            user = userList[i];
            withdrawal = getWithdrawalSafe(user, IStrategy.WithdrawalType.OneCoin);
            if (withdrawal.lpShares == 0) continue;

            lpSharesTotals[withdrawal.tokenIndex] += withdrawal.lpShares;
        }

        uint256[POOL_ASSETS] memory prevBalances = calcPrevTokenBalances();

        for (uint256 i = 0; i < POOL_ASSETS; i++) {
            if (lpSharesTotals[i] == 0) continue;
            uint256[POOL_ASSETS] memory withdrawnTokens;
            withdrawnTokens[i] = lpSharesTotals[i];
            if (
                !strategy.withdraw(
                    address(this),
                    calcLpRatioSafe(lpSharesTotals[i], _poolInfo[defaultWithdrawPid].lpShares),
                    minAmountsTotal,
                    IStrategy.WithdrawalType.OneCoin,
                    uint128(i)
                )
            ) {
                removeAllFailedWithdrawals(userList);
                return;
            }
        }

        processSuccessfulOptimizedWithdrawal(userList, lpSharesTotals, prevBalances);
    }

    function calcWithdrawOneCoin(uint256 lpShares, uint128 tokenIndex)
        external
        view
        returns (uint256 tokenAmount)
    {
        uint256 lpShareRatio = calcLpRatioSafe(lpShares, _poolInfo[defaultWithdrawPid].lpShares);
        return _poolInfo[defaultWithdrawPid].strategy.calcWithdrawOneCoin(lpShareRatio, tokenIndex);
    }

    function calcSharesAmount(uint256[POOL_ASSETS] memory tokenAmounts, bool isDeposit)
        external
        view
        returns (uint256 lpShares)
    {
        return _poolInfo[defaultWithdrawPid].strategy.calcSharesAmount(tokenAmounts, isDeposit);
    }

    struct PriceInfo {
        uint256 pid;
        uint256 price;
        uint256 holdings;
    }

    function rebalance() external onlyRole(DEFAULT_ADMIN_ROLE) {
        //calc strategy lp prices
        uint256 totalHoldings = 0;
        PriceInfo[] memory prices = new PriceInfo[](_poolInfo.length);
        for (uint256 i = 0; i < _poolInfo.length; i++) {
            PoolInfo memory poolInfo = _poolInfo[i];
            if (poolInfo.lpShares == 0) continue;
            uint256 holdings = poolInfo.strategy.totalHoldings();
            prices[i] = PriceInfo(i, calcTokenPrice(holdings, poolInfo.lpShares), holdings);
            totalHoldings += holdings;
        }

        //cache protocol lp price
        uint256 commonPrice = calcTokenPrice(totalHoldings, totalSupply());

        //descendant sort of prices
        PriceInfo[] memory sortedPrices = sortPrices(prices);

        uint256 boundary = sortedPrices.length - 1;
        for (uint256 i = 0; i <= boundary; i++) {
            PriceInfo memory lowerPrice = sortedPrices[i];
            if (lowerPrice.price == 0) continue;
            if (lowerPrice.price >= commonPrice) break;

            PoolInfo storage lowerPool = _poolInfo[lowerPrice.pid];
            uint256 lowerTokenDiff = calcTokenDiff(
                lowerPool.lpShares,
                commonPrice,
                lowerPrice.holdings
            );
            lowerPool.lpShares -= lowerTokenDiff;

            for (uint256 j = boundary; j >= i + 1; j--) {
                PriceInfo memory higherPrice = sortedPrices[j];
                if (higherPrice.price == 0) continue;
                if (higherPrice.price <= commonPrice) break;

                PoolInfo storage higherPool = _poolInfo[higherPrice.pid];
                uint256 higherTokenDiff = calcTokenDiff(
                    higherPool.lpShares,
                    commonPrice,
                    higherPrice.holdings
                );
                if (higherTokenDiff >= lowerTokenDiff) {
                    higherPool.lpShares += lowerTokenDiff;
                    lowerTokenDiff = 0;
                    break;
                }

                higherPool.lpShares += higherTokenDiff;
                lowerTokenDiff -= higherTokenDiff;
                boundary -= 1;
            }

            // give back unused lps
            if (lowerTokenDiff > 0) {
                lowerPool.lpShares += lowerTokenDiff;
            }
        }
    }

    function calcTokenDiff(
        uint256 shares,
        uint256 price,
        uint256 value
    ) internal pure returns (uint256) {
        uint256 balancedShares = (value * 1e18) / price;
        return shares > balancedShares ? shares - balancedShares : balancedShares - shares;
    }

    function sortPrices(PriceInfo[] memory arr) private pure returns (PriceInfo[] memory) {
        uint256 l = arr.length;
        for (uint256 i = 0; i < l; i++) {
            for (uint256 j = i + 1; j < l; j++) {
                if (arr[i].price > arr[j].price) (arr[i], arr[j]) = (arr[j], arr[i]);
            }
        }
        return arr;
    }

    /**
     * @dev add a new pool, deposits in the new pool are blocked for one day for safety
     * @param _strategyAddr - the new pool strategy address
     */
    function addPool(address _strategyAddr) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_strategyAddr != address(0), 'MevProtocol: zero strategy addr');
        uint256 startTime = block.timestamp + (launched ? MIN_LOCK_TIME : 0);
        _poolInfo.push(
            PoolInfo({
                strategy: IStrategy(_strategyAddr),
                startTime: startTime,
                lpShares: 0,
                enabled: true
            })
        );
        emit AddedPool(_poolInfo.length - 1, _strategyAddr, startTime);
    }

    /**
     * @dev set a default pool for deposit funds
     * @param _newPoolId - new pool id
     */
    function setDefaultDepositPid(uint256 _newPoolId)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        enabledPool(_newPoolId)
    {
        require(_newPoolId < _poolInfo.length, 'MevProtocol: incorrect default deposit pool id');

        defaultDepositPid = _newPoolId;
        emit SetDefaultDepositPid(_newPoolId);
    }

    /**
     * @dev set a default pool for withdraw funds
     * @param _newPoolId - new pool id
     */
    function setDefaultWithdrawPid(uint256 _newPoolId)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        enabledPool(_newPoolId)
    {
        require(_newPoolId < _poolInfo.length, 'MevProtocol: incorrect default withdraw pool id');

        defaultWithdrawPid = _newPoolId;
        emit SetDefaultWithdrawPid(_newPoolId);
    }

    function launch() external onlyRole(DEFAULT_ADMIN_ROLE) {
        launched = true;
    }

    /**
     * @dev dev can transfer funds from few strategy's to one strategy for better APY
     * @param _strategies - array of strategy's, from which funds are withdrawn
     * @param withdrawalsPercents - A percentage of the funds that should be transfered
     * @param _receiverStrategyId - number strategy, to which funds are deposited
     */
    function moveFundsBatch(
        uint256[] memory _strategies,
        uint256[] memory withdrawalsPercents,
        uint256 _receiverStrategyId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) enabledPool(_receiverStrategyId) {
        require(
            _strategies.length == withdrawalsPercents.length,
            'MevProtocol: incorrect arguments for the moveFundsBatch'
        );
        require(_receiverStrategyId < _poolInfo.length, 'MevProtocol: incorrect a reciver strategy ID');

        uint256[POOL_ASSETS] memory tokenBalance;
        for (uint256 y = 0; y < POOL_ASSETS; y++) {
            tokenBalance[y] = IERC20Metadata(tokens[y]).balanceOf(address(this));
        }

        uint256 pid;
        uint256 MevProtocolLp;
        for (uint256 i = 0; i < _strategies.length; i++) {
            pid = _strategies[i];
            MevProtocolLp += _moveFunds(pid, withdrawalsPercents[i]);
        }

        uint256[POOL_ASSETS] memory tokensRemainder;
        for (uint256 y = 0; y < POOL_ASSETS; y++) {
            tokensRemainder[y] =
                IERC20Metadata(tokens[y]).balanceOf(address(this)) -
                tokenBalance[y];
            if (tokensRemainder[y] > 0) {
                IERC20Metadata(tokens[y]).safeTransfer(
                    address(_poolInfo[_receiverStrategyId].strategy),
                    tokensRemainder[y]
                );
            }
        }

        _poolInfo[_receiverStrategyId].lpShares += MevProtocolLp;

        require(
            _poolInfo[_receiverStrategyId].strategy.deposit(tokensRemainder) > 0,
            'MevProtocol: Too low amount!'
        );
    }

    function _moveFunds(uint256 pid, uint256 withdrawAmount) private returns (uint256) {
        uint256 currentLpAmount;

        if (withdrawAmount == FUNDS_DENOMINATOR) {
            _poolInfo[pid].strategy.withdrawAll();

            currentLpAmount = _poolInfo[pid].lpShares;
            _poolInfo[pid].lpShares = 0;
        } else {
            currentLpAmount = (_poolInfo[pid].lpShares * withdrawAmount) / FUNDS_DENOMINATOR;
            uint256[POOL_ASSETS] memory minAmounts;

            _poolInfo[pid].strategy.withdraw(
                address(this),
                calcLpRatioSafe(currentLpAmount, _poolInfo[pid].lpShares),
                minAmounts,
                IStrategy.WithdrawalType.Base,
                0
            );
            _poolInfo[pid].lpShares = _poolInfo[pid].lpShares - currentLpAmount;
        }

        return currentLpAmount;
    }

    /**
     * @dev user remove his active pending deposit
     */
    function removePendingDeposit() external {
        for (uint256 i = 0; i < POOL_ASSETS; i++) {
            if (_pendingDeposits[_msgSender()][i] > 0) {
                IERC20Metadata(tokens[i]).safeTransfer(
                    _msgSender(),
                    _pendingDeposits[_msgSender()][i]
                );
            }
        }
        delete _pendingDeposits[_msgSender()];
        emit RemovedPendingDeposit(_msgSender());
    }

    function removePendingWithdrawal() external {
        delete _pendingWithdrawals[_msgSender()];
        emit RemovedPendingWithdrawal(_msgSender());
    }

    /**
     * @dev governance can withdraw all stuck funds in emergency case
     * @param _token - IERC20Metadata token that should be fully withdraw from MevProtocol
     */
    function withdrawStuckToken(IERC20Metadata _token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 tokenBalance = _token.balanceOf(address(this));
        if (tokenBalance > 0) {
            _token.safeTransfer(_msgSender(), tokenBalance);
        }
    }

    // Get bit value at position
    function checkBit(uint8 mask, uint8 bit) internal pure returns (bool) {
        return mask & (0x01 << bit) != 0;
    }

    function togglePoolStatus(uint256 poolIndex) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(poolIndex < _poolInfo.length, 'MevProtocol: incorrect an index of the pool');
        require(
            poolIndex != defaultDepositPid && poolIndex != defaultWithdrawPid,
            'MevProtocol: current pool is set as deposit/withdraw default pool'
        );

        _poolInfo[poolIndex].enabled = !_poolInfo[poolIndex].enabled;

        emit ToggledEnabledPoolStatus(
            address(_poolInfo[poolIndex].strategy),
            _poolInfo[poolIndex].enabled
        );
    }
}