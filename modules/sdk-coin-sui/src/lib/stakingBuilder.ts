import { BaseCoin as CoinConfig } from '@bitgo/statics';
import { InvalidTransactionError, NotSupported, TransactionType } from '@bitgo/sdk-core';
import {
  MethodNames,
  ModulesNames,
  MoveCallTx,
  MoveCallTxDetails,
  RequestAddDelegation,
  RequestSwitchDelegation,
  RequestWithdrawDelegation,
  SuiObjectRef,
  SuiTransaction,
  SuiTransactionType,
} from './iface';
import { TransactionBuilder } from './transactionBuilder';
import { SUI_PACKAGE, SUI_SYSTEM_STATE_OBJECT } from './constants';
import { SuiMoveCallTransactionSchema } from './txnSchema';
import { StakingTransaction } from './stakingTransaction';
import { Transaction } from './transaction';
import BigNumber from 'bignumber.js';
import utils from './utils';

export class StakingBuilder extends TransactionBuilder<MoveCallTx> {
  protected _moveCallTx: MoveCallTx;
  protected _addDelegationTx: RequestAddDelegation;
  protected _withdrawDelegation: RequestWithdrawDelegation;
  protected _switchDelegation: RequestSwitchDelegation;

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
    this._transaction = new StakingTransaction(_coinConfig);
  }

  /**
   * Build a MoveCall transaction ready to be signed and executed.
   *
   * @returns {SuiTransaction} an unsigned Sui transaction
   *
   * @see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/docs/sui_system.md#function-request_add_delegation_mul_coin
   */
  protected buildStakeTransaction(): SuiTransaction<MoveCallTx> {
    return {
      type: SuiTransactionType.AddDelegation,
      sender: this._sender,
      tx: this._moveCallTx,
      gasBudget: this._gasBudget,
      gasPrice: this._gasPrice,
      gasPayment: this._gasPayment,
    };
  }

  /**
   * Get staking transaction type
   *
   * @return {TransactionType}
   * @protected
   */
  protected get transactionType(): TransactionType {
    return utils.getTransactionType(this._moveCallTx.function);
  }

  /**
   * Create a new transaction for delegating coins ready to be signed and executed.
   *
   * @param {RequestAddDelegation} addDelegation
   */
  requestAddDelegation(addDelegation: RequestAddDelegation): this {
    this.validateAddress({ address: addDelegation.validatorAddress });
    this.validateValue(BigNumber(addDelegation.amount));
    for (const coin of addDelegation.coins) {
      this.validateSuiObjectRef(coin, 'addDelegation.coins');
    }
    this._addDelegationTx = addDelegation;
    this._moveCallTx = {
      package: SUI_PACKAGE,
      module: ModulesNames.SuiSystem,
      function: MethodNames.RequestAddDelegationMulCoin,
      typeArguments: [],
      arguments: [SUI_SYSTEM_STATE_OBJECT, addDelegation.coins, addDelegation.amount, addDelegation.validatorAddress],
    };
    return this;
  }

  /**
   * Create a new transaction for withdrawing coins ready to be signed
   *
   * @param {RequestWithdrawDelegation} addDelegationTx
   */
  requestWithdrawDelegation(withdrawDelegation: RequestWithdrawDelegation): this {
    this.validateSuiObjectRef(withdrawDelegation.delegation, 'withdrawDelegation.delegation');
    this.validateSuiObjectRef(withdrawDelegation.stakedCoinId, 'withdrawDelegation.stakedCoinId');

    this._withdrawDelegation = withdrawDelegation;
    this._moveCallTx = {
      package: SUI_PACKAGE,
      module: ModulesNames.SuiSystem,
      function: MethodNames.RequestWithdrawDelegation,
      typeArguments: [],
      arguments: [SUI_SYSTEM_STATE_OBJECT, withdrawDelegation.delegation, withdrawDelegation.stakedCoinId],
    };
    return this;
  }

  /**
   * Create a new transaction for switching delegation ready to be signed
   *
   * @param {switchDelegation} switchDelegation
   */
  requestSwitchDelegation(switchDelegation: RequestSwitchDelegation): this {
    this.validateSuiObjectRef(switchDelegation.delegation, 'switchDelegation.delegation');
    this.validateSuiObjectRef(switchDelegation.stakedCoinId, 'switchDelegation.stakedCoinId');
    this.validateAddress({ address: switchDelegation.newValidatorAddress });

    this._switchDelegation = switchDelegation;
    this._moveCallTx = {
      package: SUI_PACKAGE,
      module: ModulesNames.SuiSystem,
      function: MethodNames.RequestSwitchDelegation,
      typeArguments: [],
      arguments: [
        SUI_SYSTEM_STATE_OBJECT,
        switchDelegation.delegation,
        switchDelegation.stakedCoinId,
        switchDelegation.newValidatorAddress,
      ],
    };
    return this;
  }

  /** @inheritdoc */
  protected fromImplementation(rawTransaction: string): Transaction<MoveCallTx> {
    const tx = new StakingTransaction(this._coinConfig);
    this.validateRawTransaction(rawTransaction);
    tx.fromRawTransaction(rawTransaction);
    this.initBuilder(tx);
    return this.transaction;
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction<MoveCallTx>> {
    this.transaction.setSuiTransaction(this.buildSuiTransaction());
    this.transaction.transactionType(this.transactionType);

    if (this._signer) {
      this.transaction.sign(this._signer);
    }

    this._signatures.forEach((signature) => {
      this.transaction.addSignature(signature.publicKey, signature.signature);
    });

    this.transaction.loadInputsAndOutputs();
    return this.transaction;
  }

  /**
   * Initialize the transaction builder fields using the decoded transaction data
   *
   * @param {StakingTransaction} tx the transaction data
   */
  initBuilder(tx: StakingTransaction): void {
    this._transaction = tx;

    if (tx.signature && tx.signature.length > 0) {
      this._signatures = [tx.suiSignature];
    }

    const txData = tx.toJson();
    this.gasBudget(txData.gasBudget);
    this.sender(txData.sender);
    this.gasPayment(txData.gasPayment);

    const txDetails = txData.kind.Single as MoveCallTxDetails;
    if (txDetails.hasOwnProperty('Call')) {
      switch (txDetails.Call.function) {
        case MethodNames.RequestAddDelegationMulCoin:
          this.type(SuiTransactionType.AddDelegation);
          this.requestAddDelegation({
            coins: txDetails.Call.arguments[1] as SuiObjectRef[],
            amount: Number(txDetails.Call.arguments[2]),
            validatorAddress: txDetails.Call.arguments[3].toString(),
          });
          break;
        case MethodNames.RequestWithdrawDelegation:
          this.type(SuiTransactionType.WithdrawDelegation);
          this.requestWithdrawDelegation({
            delegation: txDetails.Call.arguments[1] as SuiObjectRef,
            stakedCoinId: txDetails.Call.arguments[2] as SuiObjectRef,
            amount: this._withdrawDelegation?.amount || 0,
          });
          break;
        case MethodNames.RequestSwitchDelegation:
          this.type(SuiTransactionType.SwitchDelegation);
          this.requestSwitchDelegation({
            delegation: txDetails.Call.arguments[1] as SuiObjectRef,
            stakedCoinId: txDetails.Call.arguments[2] as SuiObjectRef,
            newValidatorAddress: txDetails.Call.arguments[3].toString(),
            amount: this._withdrawDelegation?.amount || 0,
          });
          break;
        default:
          throw new NotSupported(`${txDetails.Call.function} not supported`);
      }
    } else {
      throw new Error('Transaction type not supported: ' + txDetails);
    }
  }

  /** @inheritdoc */
  validateTransaction(tx: Transaction<MoveCallTx>): void {
    this.validateSchema({
      type: this._type,
      sender: this._sender,
      tx: this._moveCallTx,
      gasPrice: this._gasPrice,
      gasBudget: this._gasBudget,
      gasPayment: this._gasPayment,
    });
  }

  /**
   * Validate transaction schema
   *
   * @param {SuiTransaction<MoveCallTx>} tx
   * @private
   */
  private validateSchema(tx: SuiTransaction<MoveCallTx>): void {
    const validationResult = SuiMoveCallTransactionSchema.validate(tx);
    if (validationResult.error) {
      throw new InvalidTransactionError(
        `Stake Builder Transaction validation failed: ${validationResult.error.message}`
      );
    }
  }

  /**
   * Build SuiTransaction
   *
   * @return {SuiTransaction<MoveCallTx>}
   * @protected
   */
  protected buildSuiTransaction(): SuiTransaction<MoveCallTx> {
    this.validateTransaction(this._transaction);
    return {
      type: this._type,
      sender: this._sender,
      tx: this._moveCallTx,
      gasBudget: this._gasBudget,
      gasPrice: this._gasPrice,
      gasPayment: this._gasPayment,
    };
  }
}
