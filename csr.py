#!/usr/bin/env python

import tkinter as tk
from tkinter import filedialog
import pyperclip
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import SubjectAlternativeName

def generate_key_and_csr():
    # Retrieve input data from the GUI fields
    common_name = entry_common_name.get()
    organizational_unit = entry_organizational_unit.get()
    country = entry_country.get()
    state = entry_state.get()
    city = entry_city.get()
    organization = entry_organization.get()
    email = entry_email.get()
    san = entry_san.get()

    # Create a key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create a subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Create a SAN (Subject Alternative Name) if provided
    san_extension = None
    if san:
        san_list = [x509.DNSName(name.strip()) for name in san.split(',')]
        san_extension = x509.SubjectAlternativeName(san_list)

    # Create a CSR with optional SAN
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if san_extension:
        builder = builder.add_extension(san_extension, critical=False)
    csr = builder.sign(private_key, hashes.SHA256())

    # Ask user to select the directory to save files
    save_dir = filedialog.askdirectory()

    if save_dir:
        # Save the private key to a .key file
        with open(f"{save_dir}/{common_name}.key", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save the CSR to a .csr file
        with open(f"{save_dir}/{common_name}.csr", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        # Inform that both key and CSR have been generated
        label_status.config(text=f"Private key and CSR generated for {common_name} in {save_dir}")

def show_openssl_commands():
    # Retrieve input data from the GUI fields
    common_name = entry_common_name.get()
    organizational_unit = entry_organizational_unit.get()
    country = entry_country.get()
    state = entry_state.get()
    city = entry_city.get()
    organization = entry_organization.get()
    email = entry_email.get()
    san = entry_san.get()

    # Create a subject
    subject = f"/C={country}/ST={state}/L={city}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"

    # Create a SAN if provided
    san_extension = ""
    if san:
        san_list = [f"DNS:{name.strip()}" for name in san.split(',')]
        san_extension = f"subjectAltName={','.join(san_list)}"

    # Create the OpenSSL command
    openssl_command = f"openssl req -new -keyout {common_name}.key -out {common_name}.csr -nodes -subj '{subject}'"
    if san_extension:
        openssl_command += f" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\n{san_extension}'))"

    # Display the OpenSSL command
    command_text.delete(1.0, tk.END)
    command_text.insert(tk.END, openssl_command)

# Create the GUI
window = tk.Tk()
window.title("Key and CSR Generator")

# Define entry fields for different details
label_common_name = tk.Label(window, text="Common Name:")
label_common_name.pack()
entry_common_name = tk.Entry(window)
entry_common_name.pack()

label_organizational_unit = tk.Label(window, text="Organizational Unit:")
label_organizational_unit.pack()
entry_organizational_unit = tk.Entry(window)
entry_organizational_unit.pack()

label_country = tk.Label(window, text="Country:")
label_country.pack()
entry_country = tk.Entry(window)
entry_country.pack()

label_state = tk.Label(window, text="State:")
label_state.pack()
entry_state = tk.Entry(window)
entry_state.pack()

label_city = tk.Label(window, text="City:")
label_city.pack()
entry_city = tk.Entry(window)
entry_city.pack()

label_organization = tk.Label(window, text="Organization:")
label_organization.pack()
entry_organization = tk.Entry(window)
entry_organization.pack()

label_email = tk.Label(window, text="Email:")
label_email.pack()
entry_email = tk.Entry(window)
entry_email.pack()

label_san = tk.Label(window, text="Subject Alternative Name (SAN):")
label_san.pack()
entry_san = tk.Entry(window)
entry_san.pack()

generate_button = tk.Button(window, text="Generate Key and CSR", command=generate_key_and_csr)
generate_button.pack()

openssl_button = tk.Button(window, text="Show OpenSSL Commands", command=show_openssl_commands)
openssl_button.pack()

label_status = tk.Label(window, text="")
label_status.pack()

command_text = tk.Text(window, height=10, width=80)
command_text.pack()

window.mainloop()
