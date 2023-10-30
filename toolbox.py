#!/usr/bin/env python

import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import SubjectAlternativeName

def generate_key_and_csr():
    common_name = entry_common_name.get()
    organizational_unit = entry_organizational_unit.get()
    country = entry_country.get()
    state = entry_state.get()
    city = entry_city.get()
    organization = entry_organization.get()
    email = entry_email.get()
    san = entry_san.get()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    san_extension = None
    if san:
        san_list = [x509.DNSName(name.strip()) for name in san.split(',')]
        san_extension = x509.SubjectAlternativeName(san_list)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if san_extension:
        builder = builder.add_extension(san_extension, critical=False)
    csr = builder.sign(private_key, hashes.SHA256())

    save_dir = filedialog.askdirectory()

    if save_dir:
        with open(f"{save_dir}/{common_name}.key", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(f"{save_dir}/{common_name}.csr", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        label_status.config(text=f"Private key and CSR generated for {common_name} in {save_dir}")

def show_openssl_commands():
    common_name = entry_common_name.get()
    organizational_unit = entry_organizational_unit.get()
    country = entry_country.get()
    state = entry_state.get()
    city = entry_city.get()
    organization = entry_organization.get()
    email = entry_email.get()
    san = entry_san.get()

    subject = f"/C={country}/ST={state}/L={city}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"

    san_extension = ""
    if san:
        san_list = [f"DNS:{name.strip()}" for name in san.split(',')]
        san_extension = f"subjectAltName={','.join(san_list)}"

    openssl_command = f"openssl req -new -keyout {common_name}.key -out {common_name}.csr -nodes -subj '{subject}'"
    if san_extension:
        openssl_command += f" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\n{san_extension}'))"

    command_text.delete(1.0, tk.END)
    command_text.insert(tk.END, openssl_command)

def create_csr_generator(sub_tab_control):
    csr_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(csr_tab, text="CSR Generator")

    label_common_name = tk.Label(csr_tab, text="Common Name:")
    label_common_name.pack()
    global entry_common_name
    entry_common_name = tk.Entry(csr_tab)
    entry_common_name.pack()

    label_organizational_unit = tk.Label(csr_tab, text="Organizational Unit:")
    label_organizational_unit.pack()
    global entry_organizational_unit
    entry_organizational_unit = tk.Entry(csr_tab)
    entry_organizational_unit.pack()

    label_country = tk.Label(csr_tab, text="Country:")
    label_country.pack()
    global entry_country
    entry_country = tk.Entry(csr_tab)
    entry_country.pack()

    label_state = tk.Label(csr_tab, text="State:")
    label_state.pack()
    global entry_state
    entry_state = tk.Entry(csr_tab)
    entry_state.pack()

    label_city = tk.Label(csr_tab, text="City:")
    label_city.pack()
    global entry_city
    entry_city = tk.Entry(csr_tab)
    entry_city.pack()

    label_organization = tk.Label(csr_tab, text="Organization:")
    label_organization.pack()
    global entry_organization
    entry_organization = tk.Entry(csr_tab)
    entry_organization.pack()

    label_email = tk.Label(csr_tab, text="Email:")
    label_email.pack()
    global entry_email
    entry_email = tk.Entry(csr_tab)
    entry_email.pack()

    label_san = tk.Label(csr_tab, text="Subject Alternative Name (SAN):")
    label_san.pack()
    global entry_san
    entry_san = tk.Entry(csr_tab)
    entry_san.pack()

    generate_button = tk.Button(csr_tab, text="Generate Key and CSR", command=generate_key_and_csr)
    generate_button.pack()

    openssl_button = tk.Button(csr_tab, text="Show OpenSSL Commands", command=show_openssl_commands)
    openssl_button.pack()

    global label_status
    label_status = tk.Label(csr_tab, text="")
    label_status.pack()

    global command_text
    command_text = tk.Text(csr_tab, height=10, width=80)
    command_text.pack()

def main():
    window = tk.Tk()
    window.title("Toolbox")

    tab_control = ttk.Notebook(window)
    tab_control.pack(fill="both", expand=True)

    ssl_tab = ttk.Frame(tab_control)
    tab_control.add(ssl_tab, text="SSL")

    sub_tab_control = ttk.Notebook(ssl_tab)
    sub_tab_control.pack(fill="both", expand=True)

    create_csr_generator(sub_tab_control)

    window.mainloop()

if __name__ == "__main__":
    main()
