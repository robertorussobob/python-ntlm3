import base64
import ntlm
from smtplib import SMTPException, SMTPAuthenticationError


def ntlm_authenticate(smtp, username, password, domain_name=None):

    code, response = smtp.docmd(
        "AUTH",
        "NTLM "  + ntlm.create_NTLM_NEGOTIATE_MESSAGE(username).decode('utf-8')
    )

    if code != 334:

        raise SMTPException("Server did not respond as exected to NTLM negotiate message")

    challenge, flags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(response.decode('utf-8'))

    code, response = smtp.docmd("", ntlm.create_NTLM_AUTHENTICATE_MESSAGE(challenge, 
                            username, 
                            domain_name, 
                            password, flags
                    ).decode('utf-8')
    )

    if code != 235:
        
        raise SMTPAuthenticationError(code, response)
