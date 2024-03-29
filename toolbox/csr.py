#!/usr/bin/env python
import tkinter as tk
import datetime
import uuid
import traceback
from tkinter import filedialog
from tkinter import ttk
from tkinter import simpledialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import SubjectAlternativeName
from cryptography.x509 import load_pem_x509_certificate

window = None

def select_file(text_widget):
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        with open(file_path, 'r') as file:
            content = file.read()
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, content)

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

def decode_csr(pasted_csr=None):
    if not pasted_csr:
        file_path = filedialog.askopenfilename()  # Prompt user to select a CSR file
        if not file_path:
            label_decoded_csr.config(text="No CSR file selected")
            return

        with open(file_path, 'rb') as csr_file:
            content = csr_file.read()
    else:
        content = pasted_csr.encode('utf-8')

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

def decode_pasted_csr():
    pasted_csr = entry_paste_csr.get("1.0", "end-1c")
    decode_csr(pasted_csr)

def create_csr_decoder(sub_tab_control):
    csr_decoder_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(csr_decoder_tab, text="CSR Decoder")

    label_select_csr = tk.Label(csr_decoder_tab, text="Select CSR File:")
    label_select_csr.pack()

    button_browse = tk.Button(csr_decoder_tab, text="Browse CSR File", command=decode_csr)
    button_browse.pack()

    label_paste_csr = tk.Label(csr_decoder_tab, text="Or Paste CSR:")
    label_paste_csr.pack()

    global entry_paste_csr
    entry_paste_csr = tk.Text(csr_decoder_tab, height=10, width=80)
    entry_paste_csr.pack()

    button_decode_paste = tk.Button(csr_decoder_tab, text="Decode Pasted CSR", command=decode_pasted_csr)
    button_decode_paste.pack()

    global label_decoded_csr
    label_decoded_csr = tk.Label(csr_decoder_tab, text="Decoded CSR content will be displayed here")
    label_decoded_csr.pack()

    return csr_decoder_tab


def decode_cert(pasted_cert=None):
    if not pasted_cert:
        file_path = filedialog.askopenfilename()  # Prompt user to select a certificate file
        if not file_path:
            label_decoded_cert.config(text="No certificate file selected")
            return

        with open(file_path, 'rb') as cert_file:
            content = cert_file.read()
    else:
        content = pasted_cert.encode('utf-8')

    try:
        cert = x509.load_pem_x509_certificate(content)

        cert_info = {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Serial Number": cert.serial_number,
            "Not Before": cert.not_valid_before,
            "Not After": cert.not_valid_after
        }

        decoded_content = "Certificate Information:\n"
        for key, value in cert_info.items():
            decoded_content += f"{key}: {value}\n"

        # Display the decoded certificate content
        label_decoded_cert.config(text=decoded_content)
    except Exception as e:
        label_decoded_cert.config(text=f"Error decoding certificate: {e}")

def decode_pasted_cert():
    pasted_cert = entry_paste_cert.get("1.0", "end-1c")
    decode_cert(pasted_cert)

def create_cert_decoder(sub_tab_control):
    cert_decoder_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(cert_decoder_tab, text="CERT Decoder")

    label_select_cert = tk.Label(cert_decoder_tab, text="Select Certificate File:")
    label_select_cert.pack()

    button_browse = tk.Button(cert_decoder_tab, text="Browse Certificate File", command=decode_cert)
    button_browse.pack()

    label_paste_cert = tk.Label(cert_decoder_tab, text="Or Paste Certificate:")
    label_paste_cert.pack()

    global entry_paste_cert
    entry_paste_cert = tk.Text(cert_decoder_tab, height=10, width=80)
    entry_paste_cert.pack()

    button_decode_paste = tk.Button(cert_decoder_tab, text="Decode Pasted Certificate", command=decode_pasted_cert)
    button_decode_paste.pack()

    global label_decoded_cert
    label_decoded_cert = tk.Label(cert_decoder_tab, text="Decoded Certificate content will be displayed here")
    label_decoded_cert.pack()

    return cert_decoder_tab

def match_certificate_with_key():
    cert_content = None
    key_content = None

    if entry_paste_cert.get("1.0", tk.END).strip() and entry_paste_key.get("1.0", tk.END).strip():
        cert_content = entry_paste_cert.get("1.0", tk.END).encode('utf-8')
        key_content = entry_paste_key.get("1.0", tk.END).encode('utf-8')

    if not cert_content or not key_content:
        cert_file_path = filedialog.askopenfilename(title="Select Certificate File")
        key_file_path = filedialog.askopenfilename(title="Select Private Key File")

        if cert_file_path and key_file_path:
            with open(cert_file_path, 'rb') as cert_file, open(key_file_path, 'rb') as key_file:
                cert_content = cert_file.read()
                key_content = key_file.read()

    if cert_content and key_content:
        try:
            cert = x509.load_pem_x509_certificate(cert_content)
            key = serialization.load_pem_private_key(key_content, password=None)

            cert_public_key = cert.public_key()
            key_public_key = key.public_key()

            if cert_public_key == key_public_key:
                label_key_match_status.config(text="Certificate and Key Match!")
            else:
                label_key_match_status.config(text="Certificate and Key Do Not Match!")
        except Exception as e:
            label_key_match_status.config(text=f"Error: {e}")
    else:
        label_key_match_status.config(text="Please select both Certificate and Key files or paste them")

def match_csr_with_key():
    csr_content = None
    key_content = None

    if entry_paste_cert.get("1.0", tk.END).strip() and entry_paste_key.get("1.0", tk.END).strip():
        csr_content = entry_paste_cert.get("1.0", tk.END).encode('utf-8')
        key_content = entry_paste_key.get("1.0", tk.END).encode('utf-8')

    if not csr_content or not key_content:
        csr_file_path = filedialog.askopenfilename(title="Select CSR File")
        key_file_path = filedialog.askopenfilename(title="Select Private Key File")

        if csr_file_path and key_file_path:
            with open(csr_file_path, 'rb') as csr_file, open(key_file_path, 'rb') as key_file:
                csr_content = csr_file.read()
                key_content = key_file.read()

    if csr_content and key_content:
        try:
            csr = x509.load_pem_x509_csr(csr_content)
            key = serialization.load_pem_private_key(key_content, password=None)

            csr_public_key = csr.public_key()
            key_public_key = key.public_key()

            if csr_public_key == key_public_key:
                label_key_match_status.config(text="CSR and Key Match!")
            else:
                label_key_match_status.config(text="CSR and Key Do Not Match!")
        except Exception as e:
            label_key_match_status.config(text=f"Error: {e}")
    else:
        label_key_match_status.config(text="Please select both CSR and Key files or paste them")

def create_cert_key_matcher(sub_tab_control):
    cert_key_matcher_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(cert_key_matcher_tab, text="Cert/CSR-Key Matcher")

    label_select_cert_csr = tk.Label(cert_key_matcher_tab, text="Upload Certificate/CSR File:")
    label_select_cert_csr.pack()

    button_select_cert_csr = tk.Button(cert_key_matcher_tab, text="Select Certificate/CSR File", command=lambda: select_file(entry_paste_cert))
    button_select_cert_csr.pack()

    label_paste_cert_csr = tk.Label(cert_key_matcher_tab, text="Or Paste Certificate/CSR:")
    label_paste_cert_csr.pack()

    global entry_paste_cert
    entry_paste_cert = tk.Text(cert_key_matcher_tab, height=10, width=80)
    entry_paste_cert.pack()

    label_select_key = tk.Label(cert_key_matcher_tab, text="Upload Private Key File:")
    label_select_key.pack()

    button_select_key = tk.Button(cert_key_matcher_tab, text="Select Private Key File", command=lambda: select_file(entry_paste_key))
    button_select_key.pack()

    label_paste_key = tk.Label(cert_key_matcher_tab, text="Or Paste Private Key:")
    label_paste_key.pack()

    global entry_paste_key
    entry_paste_key = tk.Text(cert_key_matcher_tab, height=10, width=80)
    entry_paste_key.pack()

    button_match_cert_key = tk.Button(cert_key_matcher_tab, text="Match Certificate with Key", command=match_certificate_with_key)
    button_match_cert_key.pack()

    button_match_csr_key = tk.Button(cert_key_matcher_tab, text="Match CSR with Key", command=match_csr_with_key)
    button_match_csr_key.pack()

    global label_key_match_status
    label_key_match_status = tk.Label(cert_key_matcher_tab, text="")
    label_key_match_status.pack()

    return cert_key_matcher_tab

def select_csr_file():
    file_path = filedialog.askopenfilename(title="Select CSR File")
    if file_path:
        with open(file_path, 'rb') as file:
            content = file.read()
            entry_paste_csr.delete(1.0, tk.END)
            entry_paste_csr.insert(tk.END, content)

def select_key_file():
    file_path = filedialog.askopenfilename(title="Select Private Key File")
    if file_path:
        with open(file_path, 'rb') as file:
            content = file.read()
            entry_paste_key.delete(1.0, tk.END)
            entry_paste_key.insert(tk.END, content)

def generate_crt():
    csr_content = entry_paste_csr.get("1.0", tk.END).encode('utf-8')
    key_content = entry_paste_key.get("1.0", tk.END).encode('utf-8')
    validity_days = entry_validity_days.get()

    if csr_content and key_content and validity_days:
        try:
            csr = x509.load_pem_x509_csr(csr_content)
            key = serialization.load_pem_private_key(key_content, password=None)

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(csr.subject)
            builder = builder.issuer_name(csr.subject)  # Self-signed certificate
            builder = builder.public_key(csr.public_key())
            builder = builder.not_valid_before(datetime.datetime.utcnow())
            builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=int(validity_days)))
            builder = builder.serial_number(int(uuid.uuid4()))  # Unique serial number using UUID

            certificate = builder.sign(private_key=key, algorithm=hashes.SHA256())

            save_dir = filedialog.askdirectory()
            if save_dir:
                with open(f"{save_dir}/generated_certificate.crt", "wb") as f:
                    f.write(certificate.public_bytes(serialization.Encoding.PEM))

                label_crt_status.config(text="Certificate generated successfully!")
        except Exception as e:
            label_crt_status.config(text=f"Error generating certificate: {e}")
    else:
        label_crt_status.config(text="Please select both CSR and Key files and define the validity")

def create_crt_generator(sub_tab_control):
    crt_generator_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(crt_generator_tab, text="CRT Generator")

    label_select_csr = tk.Label(crt_generator_tab, text="Select CSR File:")
    label_select_csr.pack()

    button_select_csr = tk.Button(crt_generator_tab, text="Select CSR File", command=select_csr_file)
    button_select_csr.pack()

    global entry_paste_csr
    entry_paste_csr = tk.Text(crt_generator_tab, height=10, width=80)
    entry_paste_csr.pack()

    label_select_key = tk.Label(crt_generator_tab, text="Select Private Key File:")
    label_select_key.pack()

    button_select_key = tk.Button(crt_generator_tab, text="Select Private Key File", command=select_key_file)
    button_select_key.pack()

    global entry_paste_key
    entry_paste_key = tk.Text(crt_generator_tab, height=10, width=80)
    entry_paste_key.pack()

    label_validity_days = tk.Label(crt_generator_tab, text="Validity (in days):")
    label_validity_days.pack()
    global entry_validity_days
    entry_validity_days = tk.Entry(crt_generator_tab)
    entry_validity_days.pack()

    button_generate_crt = tk.Button(crt_generator_tab, text="Generate CRT", command=generate_crt)
    button_generate_crt.pack()

    global label_crt_status
    label_crt_status = tk.Label(crt_generator_tab, text="")
    label_crt_status.pack()

    return crt_generator_tab

def convert_cert(format_var):
    file_path = filedialog.askopenfilename(title="Select Certificate File")
    if file_path:
        save_dir = filedialog.askdirectory()
        if save_dir:
            try:
                with open(file_path, 'rb') as cert_file:
                    cert_content = cert_file.read()
                    cert = load_pem_x509_certificate(cert_content)

                    # Convert certificate to different formats
                    if format_var.get() == "PEM":
                        converted_cert = cert.public_bytes(serialization.Encoding.PEM)
                    elif format_var.get() == "DER":
                        converted_cert = cert.public_bytes(serialization.Encoding.DER)
                    elif format_var.get() == "P7B":
                        converted_cert = cert.public_bytes(serialization.Encoding.PKCS7)
                    elif format_var.get() == "PFX":
                        converted_cert = cert.public_bytes(serialization.Encoding.PKCS12)
                    else:
                        label_cert_convert_status.config(text="Please select a format!")
                        return

                    with open(f"{save_dir}/converted_certificate.{format_var.get().lower()}", "wb") as f:
                        f.write(converted_cert)
                    label_cert_convert_status.config(text="Certificate converted successfully!")
            except Exception as e:
                label_cert_convert_status.config(text=f"Error converting certificate: {e}")

def create_cert_converter(sub_tab_control):
    cert_converter_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(cert_converter_tab, text="Cert Converter")

    label_select_cert = tk.Label(cert_converter_tab, text="Select Certificate File:")
    label_select_cert.pack()

    button_select_cert = tk.Button(cert_converter_tab, text="Select Certificate File", command=lambda: convert_cert(format_var))
    button_select_cert.pack()

    global label_cert_convert_status
    label_cert_convert_status = tk.Label(cert_converter_tab, text="")
    label_cert_convert_status.pack()

    # Dropdown or Radio buttons for format selection
    format_var = tk.StringVar()
    format_var.set("PEM")  # Default format

    label_format = tk.Label(cert_converter_tab, text="Select Format to Convert:")
    label_format.pack()

    format_dropdown = tk.OptionMenu(cert_converter_tab, format_var, "PEM", "DER", "P7B", "PFX")
    format_dropdown.pack()

    return cert_converter_tab

def convert_pfx_to_pem(pfx_file, password):
    try:
        with open(pfx_file, 'rb') as file:
            pfx_content = file.read()

            try:
                pfx = serialization.load_pem_private_key(
                    pfx_content,
                    password=password.encode('utf-8'),
                    backend=default_backend()
                )

                private_key = pfx.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

                cert = pfx.public_bytes(serialization.Encoding.PEM)

                with open("private_key.pem", "wb") as key_file:
                    key_file.write(private_key)

                with open("certificate.pem", "wb") as cert_file:
                    cert_file.write(cert)

                label_pfx_convert_status.config(text="PFX file converted successfully!")
            except Exception as e:
                label_pfx_convert_status.config(text=f"Error loading PFX: {e}")
    except Exception as e:
        label_pfx_convert_status.config(text=f"Error reading PFX file: {e}")

def select_pfx_file():
    file_path = filedialog.askopenfilename(title="Select PFX File")
    if file_path:
        password = simpledialog.askstring("Password", "Enter password for PFX file", show='*')
        if password:
            convert_pfx_to_pem(file_path, password)

def create_pfx_converter(sub_tab_control):
    pfx_converter_tab = ttk.Frame(sub_tab_control)
    sub_tab_control.add(pfx_converter_tab, text="PFX Converter")

    label_select_pfx = tk.Label(pfx_converter_tab, text="Select PFX File:")
    label_select_pfx.pack()

    button_select_pfx = tk.Button(pfx_converter_tab, text="Select PFX File", command=select_pfx_file)
    button_select_pfx.pack()

    global label_pfx_convert_status
    label_pfx_convert_status = tk.Label(pfx_converter_tab, text="")
    label_pfx_convert_status.pack()

    return pfx_converter_tab

def select_icon_file():
    global window  # Access the global window variable
    file_path = filedialog.askopenfilename(title="Select Icon File")
    if file_path:
        window.iconbitmap(file_path)  # Set the window icon

def create_icon_tab(sub_gui_control):
    icon_tab = ttk.Frame(sub_gui_control)
    sub_gui_control.add(icon_tab, text="Icons")

    label_select_icon = tk.Label(icon_tab, text="Select Icon File:")
    label_select_icon.pack()

    button_select_icon = tk.Button(icon_tab, text="Select Icon File", command=select_icon_file)
    button_select_icon.pack()

    global label_icon_status
    label_icon_status = tk.Label(icon_tab, text="")
    label_icon_status.pack()

    return icon_tab

def create_gui_settings_tab(tab_control):
    gui_settings_tab = ttk.Frame(tab_control)
    tab_control.add(gui_settings_tab, text="GUI")

    icon_label = tk.Label(gui_settings_tab, text="Select Application Icon:")
    icon_label.pack()

    icon_button = tk.Button(gui_settings_tab, text="Select Icon File", command=select_icon_file)
    icon_button.pack()

def create_settings_tab(tab_control):
    settings_tab = ttk.Frame(tab_control)
    tab_control.add(settings_tab, text="Settings")

    sub_settings_control = ttk.Notebook(settings_tab)
    sub_settings_control.pack(fill="both", expand=True)

    sub_settings_control.add(create_gui_settings_tab(sub_settings_control), text="GUI")

    return settings_tab

def create_powershell_tab(tab_control):
    powershell_tab = ttk.Frame(tab_control)
    tab_control.add(powershell_tab, text="Powershell")

    sub_powershell_control = ttk.Notebook(powershell_tab)
    sub_powershell_control.pack(fill="both", expand=True)

    mail_tab = ttk.Frame(sub_powershell_control)
    sub_powershell_control.add(mail_tab, text="Mail")

    sub_mail_control = ttk.Notebook(mail_tab)
    sub_mail_control.pack(fill="both", expand=True)

    language_tab = ttk.Frame(sub_mail_control)
    sub_mail_control.add(language_tab, text="Language")

    label_mailbox = tk.Label(language_tab, text="Mailbox:")
    label_mailbox.pack()
    entry_mailbox = tk.Entry(language_tab)
    entry_mailbox.pack()

    label_language = tk.Label(language_tab, text="Language:")
    label_language.pack()

    # Dropdown box for language selection
    languages = ["English", "Spanish", "French", "German", "Dutch", "Portuguese (Brazil)"]
    selected_language = tk.StringVar(language_tab)
    selected_language.set(languages[0])  # Default language selection

    language_dropdown = tk.OptionMenu(language_tab, selected_language, *languages)
    language_dropdown.pack()

    def generate_powershell_command():
        mailbox = entry_mailbox.get()
        language = selected_language.get()


        if mailbox and language:
            # Adjusting the PowerShell command
            language_codes = {
                "English": "en-us",
                "Spanish": "es-es",
                "French": "fr-fr",
                "German": "de-de",
                "Dutch": "nl-nl",
                "Portuguese (Brazil)": "pt-br"
            }

            language_code = language_codes.get(language, "en-us")

            powershell_command = f'Connect-ExchangeOnline\nSet-MailboxRegionalConfiguration -Identity "{mailbox}" -Language {language_code} -LocalizeDefaultFolderName'
            text_powershell_command.delete(1.0, tk.END)
            text_powershell_command.insert(tk.END, powershell_command)
        else:
            text_powershell_command.delete(1.0, tk.END)
            text_powershell_command.insert(tk.END, "Please enter both Mailbox and Language")

    # Creating the "Generate PowerShell Command" button
    button_generate_powershell = tk.Button(powershell_tab, text="Generate PowerShell Command", command=generate_powershell_command)
    button_generate_powershell.pack()

    # Creating a Text widget to display the PowerShell command output
    text_powershell_command = tk.Text(powershell_tab, height=10, width=80)
    text_powershell_command.pack()

    return powershell_tab


def main():
    global window
    window = tk.Tk()
    window.title("Toolbox")

    tab_control = ttk.Notebook(window)
    tab_control.pack(fill="both", expand=True)

    ssl_tab = ttk.Frame(tab_control)
    tab_control.add(ssl_tab, text="SSL")

    sub_tab_control = ttk.Notebook(ssl_tab)
    sub_tab_control.pack(fill="both", expand=True)

    create_csr_generator(sub_tab_control)
    create_csr_check(sub_tab_control)
    decoder_tab = create_csr_decoder(sub_tab_control)  # CSR Decoder tab
    cert_decoder_tab = create_cert_decoder(sub_tab_control)  # CERT Decoder tab
    cert_key_matcher_tab = create_cert_key_matcher(sub_tab_control)
    crt_generator_tab = create_crt_generator(sub_tab_control)
    cert_converter_tab = create_cert_converter(sub_tab_control)
    pfx_converter_tab = create_pfx_converter(sub_tab_control)
    powershell_tab = create_powershell_tab(tab_control)
    tab_control.add(create_settings_tab(tab_control), text="Settings")  # Adding Settings Tab

    window.mainloop()

if __name__ == "__main__":
    main()
