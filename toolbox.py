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

def generate_key_and_csr_check():
    # Define the actions for CSR check here
    pass

def create_csr_check(sub_tab_control):
    csr_check_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(csr_check_tab, text="CSR Check")

    label_csr_file = tk.Label(csr_check_tab, text="Select CSR File:")
    label_csr_file.pack()

    def select_csr_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                label_csr_content.config(text=content)

    button_browse = tk.Button(csr_check_tab, text="Browse CSR File", command=select_csr_file)
    button_browse.pack()

    global label_csr_content
    label_csr_content = tk.Label(csr_check_tab, text="CSR content will be displayed here")
    label_csr_content.pack()

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

def decode_csr():
    file_path = filedialog.askopenfilename()  # Prompt user to select a CSR file
    if file_path:
        with open(file_path, 'rb') as csr_file:
            content = csr_file.read()

            try:
                csr = x509.load_pem_x509_csr(content)

                subject_info = {
                    "Common Name": csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                    "Country": csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value,
                    "State": csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value,
                    "Locality": csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value,
                    "Organization": csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
                    "Organizational Unit": csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value,
                    "Email": csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value,
                }

                san = []
                for ext in csr.extensions:
                    if isinstance(ext.value, x509.SubjectAlternativeName):
                        san.extend(str(name).split("'")[1] for name in ext.value if isinstance(name, x509.DNSName))

                decoded_content = "Subject Information:\n"
                for key, value in subject_info.items():
                    decoded_content += f"{key}: {value}\n"

                if san:
                    decoded_content += "\nSubject Alternative Name:\n"
                    for value in san:
                        decoded_content += f"{value}\n"

                # Display the decoded CSR content
                label_decoded_csr.config(text=decoded_content)
            except Exception as e:
                label_decoded_csr.config(text=f"Error decoding CSR: {e}")
    else:
        label_decoded_csr.config(text="No CSR file selected")


def create_csr_decoder(sub_tab_control):
    csr_decoder_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(csr_decoder_tab, text="CSR Decoder")

    label_select_csr = tk.Label(csr_decoder_tab, text="Select CSR File:")
    label_select_csr.pack()

    button_browse_csr = tk.Button(csr_decoder_tab, text="Browse CSR File", command=decode_csr)
    button_browse_csr.pack()

    global label_decoded_csr
    label_decoded_csr = tk.Label(csr_decoder_tab, text="Decoded CSR content will be displayed here")
    label_decoded_csr.pack()

    return csr_decoder_tab

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
    create_csr_check(sub_tab_control)  # Add CSR Check tab

    # Newly added line to create the CSR Decoder tab
    decoder_tab = create_csr_decoder(sub_tab_control)

    window.mainloop()

if __name__ == "__main__":
    main()
