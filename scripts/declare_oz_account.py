"""
Borrowed from the OpenZeppelin implementation 
"""


async def run(nre):
    accounts = await nre.get_accounts(predeployed=True)
    declarer_account = accounts[0]

    # nile_account flag tells Nile to use its pre-packed artifact
    #
    # If we don't pass a max_fee, nile will estimate the transaction
    # fee by default. This line is equivalent to:
    #
    # tx = await declarer_account.declare("Account", max_fee=0, nile_account=True)
    # max_fee = await tx.estimate_fee()
    # tx.update_fee(max_fee)
    #
    # Note that tx.update_fee will update tx.hash and tx.max_fee members
    tx = await declarer_account.declare("Account", nile_account=True)
    tx_status, *_ = await tx.execute(watch_mode="track")

    print(tx_status.status, tx_status.error_message or "")
