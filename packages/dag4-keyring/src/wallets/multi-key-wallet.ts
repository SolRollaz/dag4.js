
import {SimpleKeyring} from '../rings';
import {IKeyringWallet, IKeyringAccount, KeyringAssetType, KeyringNetwork, KeyringWalletSerialized, KeyringWalletType} from '../kcs';

let SID = 0;

export class MultiKeyWallet implements IKeyringWallet {

  readonly type = KeyringWalletType.MultiKeyWallet;
  readonly id = this.type + (++SID);
  readonly supportedAssets = [];

  private keyRings: SimpleKeyring[];
  private network: KeyringNetwork;
  private label: string;

  create (network: KeyringNetwork, label: string) {
    this.deserialize({ type: this.type, label, network });
  }

  setLabel(val: string) {
    this.label = val;
  }

  getLabel(): string {
    return this.label;
  }

  getNetwork () {
    return this.network;
  }

  getState () {
    return {
      id: this.id,
      type: this.type,
      label: this.label,
      supportedAssets: this.supportedAssets,
      accounts: this.getAccounts().map(a => {
        return {
          address: a.getAddress(),
          network: a.getNetwork(),
          tokens: a.getTokens()
        }
      })
    }
  }

  serialize (): KeyringWalletSerialized {
    return {
      type: this.type,
      label: this.label,
      network: this.network,
      secrets: this.keyRings.map(k => k.getAccounts()[0].getPrivateKey())
    }
  }

  deserialize (data: KeyringWalletSerialized) {

    this.label = data.label;
    this.network = data.network;
    this.keyRings = [];

    if (data.secrets && data.secrets.length) {
      data.secrets.forEach(key => this.importAccount(key));
    }

    if (this.network === KeyringNetwork.Ethereum) {
      this.supportedAssets.push(KeyringAssetType.ETH);
      this.supportedAssets.push(KeyringAssetType.ERC20);
    }
    else if (this.network === KeyringNetwork.Constellation) {
      this.supportedAssets.push(KeyringAssetType.DAG);
    }
  }

  importAccount (secret: string) {
    const keyring = new SimpleKeyring();
    keyring.deserialize({network: this.network, accounts: [{ privateKey: secret }]});
    this.keyRings.push(keyring);
    return keyring.getAccounts()[0];
  }

  getAccounts (): IKeyringAccount[] {
    return this.keyRings.reduce<IKeyringAccount[]>((res, w) => res.concat(w.getAccounts()), []);
  }

  getAccountByAddress (address: string): IKeyringAccount {
    let account: IKeyringAccount;
    this.keyRings.some(w => account = w.getAccountByAddress(address));
    return account;
  }

  removeAccount (account: IKeyringAccount) {
    //Does not support removing account
  }

  exportSecretKey(): string {
    throw new Error('MultiKeyWallet does not allow exportSecretKey');
  }

}
