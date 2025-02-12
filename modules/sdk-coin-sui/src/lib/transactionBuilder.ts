import {
  BaseAddress,
  BaseKey,
  BaseTransactionBuilder,
  BuildTransactionError,
  ParseTransactionError,
  PublicKey as BasePublicKey,
  Signature,
  TransactionType,
} from '@bitgo/sdk-core';
import { Transaction } from './transaction';
import utils from './utils';
import BigNumber from 'bignumber.js';
import { BaseCoin as CoinConfig } from '@bitgo/statics';
import { SuiObjectRef, SuiTransactionType } from './iface';
import { SUI_GAS_PRICE } from './constants';
import { KeyPair } from './keyPair';

export abstract class TransactionBuilder<T> extends BaseTransactionBuilder {
  protected _transaction: Transaction<T>;
  protected _signatures: Signature[] = [];
  protected _signer: KeyPair;

  protected _type: SuiTransactionType;
  protected _sender: string;
  protected _gasBudget: number;
  protected _gasPrice = SUI_GAS_PRICE;
  protected _gasPayment: SuiObjectRef;

  protected constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
  }

  // get and set region
  /**
   * The transaction type.
   */
  protected abstract get transactionType(): TransactionType;

  /** @inheritdoc */
  protected get transaction(): Transaction<T> {
    return this._transaction;
  }

  /** @inheritdoc */
  protected set transaction(transaction: Transaction<T>) {
    this._transaction = transaction;
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction<T> {
    const signer = new KeyPair({ prv: key.key });
    this._signer = signer;
    this.transaction.sign(signer);
    return this.transaction;
  }

  /** @inheritDoc */
  addSignature(publicKey: BasePublicKey, signature: Buffer): void {
    this._signatures.push({ publicKey, signature });
    this.transaction.addSignature(publicKey, signature);
    this.transaction.setSerializedSig(publicKey, signature);
  }

  /**
   * Sets the sender of this transaction.
   * This account will be responsible for paying transaction fees.
   *
   * @param {string} senderAddress the account that is sending this transaction
   * @returns {TransactionBuilder} This transaction builder
   */
  sender(senderAddress: string): this {
    utils.validateAddress(senderAddress, 'sender');
    this._sender = senderAddress;
    return this;
  }

  type(type: SuiTransactionType): this {
    this._type = type;
    return this;
  }

  gasBudget(gasBudget: number): this {
    this.validateGasBudget(gasBudget);
    this._gasBudget = gasBudget;
    return this;
  }

  gasPayment(gasPayment: SuiObjectRef): this {
    this.validateGasPayment(gasPayment);
    this._gasPayment = gasPayment;
    return this;
  }

  /**
   * Initialize the transaction builder fields using the decoded transaction data
   *
   * @param {Transaction} tx the transaction data
   */
  abstract initBuilder(tx: Transaction<T>): void;

  // region Validators
  /** @inheritdoc */
  validateAddress(address: BaseAddress, addressFormat?: string): void {
    if (!utils.isValidAddress(address.address)) {
      throw new BuildTransactionError('Invalid address ' + address.address);
    }
  }

  validateGasBudget(gasBudget: number): void {
    if (gasBudget <= 0) {
      throw new BuildTransactionError('Invalid gas budget ' + gasBudget);
    }
  }

  validateGasPrice(gasPrice: number): void {
    if (gasPrice !== SUI_GAS_PRICE) {
      throw new BuildTransactionError('Invalid gas price ' + gasPrice);
    }
  }

  validateGasPayment(gasPayment: SuiObjectRef): void {
    if (!gasPayment) {
      throw new BuildTransactionError(`Invalid gas Payment: undefined`);
    }
    this.validateSuiObjectRef(gasPayment, 'gasPayment');
  }

  validateSuiObjectRef(suiObjectRef: SuiObjectRef, field: string): void {
    if (!suiObjectRef.hasOwnProperty('objectId')) {
      throw new BuildTransactionError(`Invalid ${field}, missing objectId`);
    }
    if (!suiObjectRef.hasOwnProperty('version') || !utils.isValidAmount(suiObjectRef.version)) {
      throw new BuildTransactionError(`Invalid ${field}, invalid or missing version`);
    }
    if (!suiObjectRef.hasOwnProperty('digest')) {
      throw new BuildTransactionError(`Invalid ${field}, missing digest`);
    }
  }

  /** @inheritdoc */
  validateKey(key: BaseKey): void {
    try {
      new KeyPair({ prv: key.key });
    } catch {
      throw new BuildTransactionError(`Key validation failed`);
    }
  }

  /** @inheritdoc */
  validateRawTransaction(rawTransaction: string): void {
    if (!rawTransaction) {
      throw new ParseTransactionError('Invalid raw transaction: Undefined');
    }
    if (!utils.isValidRawTransaction(rawTransaction)) {
      throw new ParseTransactionError('Invalid raw transaction');
    }
  }

  /** @inheritdoc */
  validateValue(value: BigNumber): void {
    if (value.isLessThan(0)) {
      throw new BuildTransactionError('Value cannot be less than zero');
    }
  }
  // endregion
}
