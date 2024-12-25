from web3 import Web3
import requests
import json
from fake_useragent import UserAgent
from typing import Union
import time

#КОНТРАКТ НА КЛЕЙМ и АБИ!
#----------------------------------------------------------
contract_abi = '[{"inputs":[{"internalType":"bytes32","name":"_merkleRoot","type":"bytes32"},{"internalType":"address","name":"_token","type":"address"},{"internalType":"address","name":"_owner","type":"address"},{"internalType":"uint256","name":"_claimEnd","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"AddressInsufficientBalance","type":"error"},{"inputs":[],"name":"AlreadyClaimed","type":"error"},{"inputs":[],"name":"ClaimFinished","type":"error"},{"inputs":[],"name":"ClaimNotFinished","type":"error"},{"inputs":[],"name":"EmptyProof","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[],"name":"InvalidAmount","type":"error"},{"inputs":[],"name":"InvalidProof","type":"error"},{"inputs":[],"name":"InvalidToken","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"name":"SafeERC20FailedOperation","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Claimed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferStarted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdrawn","type":"event"},{"inputs":[],"name":"CLAIM_END","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MERKLE_ROOT","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TOKEN","outputs":[{"internalType":"contract IERC20","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"acceptOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes32[]","name":"_merkleProof","type":"bytes32[]"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"hasClaimed","outputs":[{"internalType":"bool","name":"claimed","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pendingOwner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
claim_contract_address = '0xE8bE8eB940c0ca3BD19D911CD3bEBc97Bea0ED62'
#----------------------------------------------------------
#КОНТРАКТ ТОКЕНА и АБИ!
token_contract_abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[{"internalType":"address","name":"delegatee","type":"address"}],"name":"DuplicateOrUnsortedDelegatees","type":"error"},{"inputs":[],"name":"ECDSAInvalidSignature","type":"error"},{"inputs":[{"internalType":"uint256","name":"length","type":"uint256"}],"name":"ECDSAInvalidSignatureLength","type":"error"},{"inputs":[{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"ECDSAInvalidSignatureS","type":"error"},{"inputs":[{"internalType":"uint256","name":"increasedSupply","type":"uint256"},{"internalType":"uint256","name":"cap","type":"uint256"}],"name":"ERC20ExceededSafeSupply","type":"error"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"allowance","type":"uint256"},{"internalType":"uint256","name":"needed","type":"uint256"}],"name":"ERC20InsufficientAllowance","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"uint256","name":"balance","type":"uint256"},{"internalType":"uint256","name":"needed","type":"uint256"}],"name":"ERC20InsufficientBalance","type":"error"},{"inputs":[{"internalType":"address","name":"approver","type":"address"}],"name":"ERC20InvalidApprover","type":"error"},{"inputs":[{"internalType":"address","name":"receiver","type":"address"}],"name":"ERC20InvalidReceiver","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"}],"name":"ERC20InvalidSender","type":"error"},{"inputs":[{"internalType":"address","name":"spender","type":"address"}],"name":"ERC20InvalidSpender","type":"error"},{"inputs":[{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"ERC2612ExpiredSignature","type":"error"},{"inputs":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"address","name":"owner","type":"address"}],"name":"ERC2612InvalidSigner","type":"error"},{"inputs":[{"internalType":"uint256","name":"timepoint","type":"uint256"},{"internalType":"uint48","name":"clock","type":"uint48"}],"name":"ERC5805FutureLookup","type":"error"},{"inputs":[],"name":"ERC6372InconsistentClock","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"currentNonce","type":"uint256"}],"name":"InvalidAccountNonce","type":"error"},{"inputs":[],"name":"InvalidAddressZero","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"InvalidNumeratorZero","type":"error"},{"inputs":[],"name":"InvalidSignature","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[{"internalType":"uint256","name":"numerator","type":"uint256"},{"internalType":"uint96","name":"denominator","type":"uint96"}],"name":"NumeratorSumExceedsDenominator","type":"error"},{"inputs":[{"internalType":"uint256","name":"length","type":"uint256"},{"internalType":"uint256","name":"max","type":"uint256"}],"name":"PartialDelegationLimitExceeded","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[{"internalType":"uint256","name":"expiry","type":"uint256"}],"name":"VotesExpiredSignature","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegator","type":"address"},{"components":[{"internalType":"address","name":"_delegatee","type":"address"},{"internalType":"uint96","name":"_numerator","type":"uint96"}],"indexed":false,"internalType":"struct PartialDelegation[]","name":"oldDelegatees","type":"tuple[]"},{"components":[{"internalType":"address","name":"_delegatee","type":"address"},{"internalType":"uint96","name":"_numerator","type":"uint96"}],"indexed":false,"internalType":"struct PartialDelegation[]","name":"newDelegatees","type":"tuple[]"}],"name":"DelegateChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegate","type":"address"},{"indexed":false,"internalType":"uint256","name":"previousVotes","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newVotes","type":"uint256"}],"name":"DelegateVotesChanged","type":"event"},{"anonymous":false,"inputs":[],"name":"EIP712DomainChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[],"name":"BURNER_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"CLOCK_MODE","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DELEGATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DENOMINATOR","outputs":[{"internalType":"uint96","name":"","type":"uint96"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MAX_PARTIAL_DELEGATIONS","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MINTER_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"PARTIAL_DELEGATION_ON_BEHALF_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"PARTIAL_DELEGATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"},{"internalType":"uint256","name":"_value","type":"uint256"}],"name":"burn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint32","name":"pos","type":"uint32"}],"name":"checkpoints","outputs":[{"components":[{"internalType":"uint48","name":"_key","type":"uint48"},{"internalType":"uint208","name":"_value","type":"uint208"}],"internalType":"struct Checkpoints.Checkpoint208","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"clock","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"delegatee","type":"address"}],"name":"delegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"address","name":"_delegatee","type":"address"},{"internalType":"uint96","name":"_numerator","type":"uint96"}],"internalType":"struct PartialDelegation[]","name":"_partialDelegations","type":"tuple[]"}],"name":"delegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"delegatee","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"expiry","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"delegateBySig","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_delegator","type":"address"},{"components":[{"internalType":"address","name":"_delegatee","type":"address"},{"internalType":"uint96","name":"_numerator","type":"uint96"}],"internalType":"struct PartialDelegation[]","name":"_partialDelegations","type":"tuple[]"},{"internalType":"uint256","name":"_nonce","type":"uint256"},{"internalType":"uint256","name":"_expiry","type":"uint256"},{"internalType":"bytes","name":"_signature","type":"bytes"}],"name":"delegatePartiallyOnBehalf","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"delegates","outputs":[{"components":[{"internalType":"address","name":"_delegatee","type":"address"},{"internalType":"uint96","name":"_numerator","type":"uint96"}],"internalType":"struct PartialDelegation[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"eip712Domain","outputs":[{"internalType":"bytes1","name":"fields","type":"bytes1"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"version","type":"string"},{"internalType":"uint256","name":"chainId","type":"uint256"},{"internalType":"address","name":"verifyingContract","type":"address"},{"internalType":"bytes32","name":"salt","type":"bytes32"},{"internalType":"uint256[]","name":"extensions","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"timepoint","type":"uint256"}],"name":"getPastTotalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"timepoint","type":"uint256"}],"name":"getPastVotes","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"getVotes","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_admin","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_symbol","type":"string"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"invalidateNonce","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"numCheckpoints","outputs":[{"internalType":"uint32","name":"","type":"uint32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'
token_contract_address = '0xd29687c813D741E2F938F4aC377128810E217b1b'
#----------------------------------------------------------
# RPC
rpc_link = '?'


def load_data(file_path) -> list:
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]


def get_eligibility_data(proxy: str, wallet_address: str, web3) -> Union[dict, list, str]:
    print(f'начал подключение к API. Кошелек {wallet_address}')
    proxies = {'http': f'http://{proxy}'}
    ua = UserAgent()
    headers = {
        'authority': 'claim.scroll.io',
        'accept': 'text/x-component',
        'accept-language': 'pl',
        'content-type': 'text/plain;charset=UTF-8',
        'next-action': '2ab5dbb719cdef833b891dc475986d28393ae963',
        'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(claim)%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%3Fstep%3D5%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
        'origin': 'https://claim.scroll.io',
        'referer': 'https://claim.scroll.io/?step=5',
        'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': ua,
    }
    params = {
        'step': '5',
    }
    data = f'["{wallet_address}"]'
    for _ in range(3):
        try:
            response = requests.post('https://claim.scroll.io/', params=params, proxies=proxies, headers=headers, data=data)
            print(response.status_code)
            response = response.text.split()
            print(response)
            response = response[-1]
            response = response[2:]
            json_data = json.loads(response)
            print(json_data)
            return json_data
        except Exception as e:
            print(f'Произошла ошибка на запросе API: {e}')
            print(f'пробую повторно подключиться аккаунт: {wallet_address}')
            time.sleep(5)
    print(f'не получилось подключиться к API. аккаунт: {wallet_address}')
    return wallet_address


def claim(account, key, eligibility_data, web3):
    print(f'начал клейм адреса: {account.address}')
    print(eligibility_data)
    for _ in range(3):
        try:
            recipient = eligibility_data['recipient']
            token_amount = eligibility_data['amount']
            merkleProof = eligibility_data['proof']
            contract = web3.eth.contract(
                address=web3.to_checksum_address(claim_contract_address),
                abi=contract_abi)
            transaction = contract.functions.claim(
                web3.to_checksum_address(recipient),
                int(token_amount),
                merkleProof
            ).build_transaction({
                'from': web3.to_checksum_address(account.address),
                'gasPrice': int(web3.eth.gas_price * 10),
                'nonce': web3.eth.get_transaction_count(account.address),
                'gas': 0
            })
            transaction['gas'] = int(web3.eth.estimate_gas(transaction) * 1.2)
            signed_txn = web3.eth.account.sign_transaction(transaction, key)
            claim_txn_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
            web3.eth.wait_for_transaction_receipt(claim_txn_hash)
            print(f'транзакция клейма прошла: {account.address}.')
            return token_amount
        except Exception as e:
            print(f'транзакция клейма не прошла: {account.address}. Ошибка: {e}')
            print(f'пробую снова')
    print(f' три попытки неудачные скипаю {account.address}')
    return account.address


def transfer_tokens(account, key, token_amount, deposit_address, web3):
    print(f'Начинаю трансфер c адреса {account.address} на {deposit_address}')
    for _ in range(3):
        try:
            token_contract = web3.eth.contract(
                address=web3.to_checksum_address(token_contract_address),
                abi=token_contract_abi
            )
            transfer_transaction = token_contract.functions.transfer(
                web3.to_checksum_address(deposit_address),
                int(token_amount)
            ).build_transaction(
                {
                    'from': account.address,
                    'gasPrice': int(web3.eth.gas_price * 5),
                    'nonce': web3.eth.get_transaction_count(account.address),
                    'gas': 0
                })
            transfer_transaction['gas'] = int(web3.eth.estimate_gas(transfer_transaction) * 5)
            signed_transfer_txn = web3.eth.account.sign_transaction(transfer_transaction, key)
            transfer_txn_hash = web3.eth.send_raw_transaction(signed_transfer_txn.raw_transaction)
            print(f'транзакция отправки прошла: {account.address}. Хеш: {transfer_txn_hash}')
            return 0
        except Exception as e:
            print(f'транзакция отправки не прошла: {account.address}. Ошибка: {e}')
            print(f'пробую снова')
    print(f' три попытки неудачные скипаю {account.address}')
    return account.address


def main(key, proxy, deposit_address, web3):
    account = web3.eth.account.from_key(key)
    eligibility_data = get_eligibility_data(wallet_address=account.address, proxy=proxy,web3=web3)
    if eligibility_data == account.address:
        return account.address

    token_amount = claim(account=account, key=key, eligibility_data=eligibility_data, web3=web3)
    if token_amount == account.address:
        return account.address

    address = transfer_tokens(
        account=account,
        key=key,
        token_amount=token_amount,
        deposit_address=deposit_address,
        web3=web3)
    if address == account.address:
        return account.address
    return token_amount


if __name__ == "__main__":
    proxy = load_data('proxy.txt')
    key = load_data('key.txt')
    deposit_address = load_data('deposit_addres.txt')
    lst_error = []
    token_amount_all = 0
    for private_key, proxy, deposit_address in zip(key, proxy, deposit_address):
        web3 = Web3(Web3.HTTPProvider(rpc_link))
        token_amount_ = main(key=private_key, proxy=proxy, deposit_address=deposit_address, web3=web3)
        if not isinstance(token_amount_, (int, float)):
            lst_error.append(key)
        if isinstance(token_amount_, (int, float)):
            token_amount_all += token_amount_
    print(f'Всего токенов склеймено: {token_amount_all}')
    with open('key_error.txt', 'w') as file:
        for item in lst_error:
            file.write(f'{item}\n')