# Manual evidence checklist
## Show encrypted payloads (no plaintext):
    Open Wireshark
    Choose 'Adapter for loopback traffic'
    apply filter: 'tcp.port==9000'
    run client.py and send message

## BAD_CERT on invalid/self/expired cert:
    swap ca.cert.pem <-> client.cert.pem
    run client.py

## SIG_FAIL on tamper (flip bit in ct):
    toggle TEST_SIG_FAIL in client.py True

## REPLAY on reused seqno:
    toggle TEST_REPLAY in client.py to True

## Transcript + signed SessionReceipt:
    run tests/trancript_test.py
    put transcript and sign mentioned in reciept at the end of clien session
