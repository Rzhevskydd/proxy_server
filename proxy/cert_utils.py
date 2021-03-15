import os
from multiprocessing import Lock
from shutil import copyfile

from proxy.common.constant import CERTS_DIR, GENERATED_CERTS_DIR, EXT_FILENAME, CSR_FILENAME, ROOT_CRTNAME, \
    ROOT_KEYNAME, CRT_FILENAME

cert_gen_lock = Lock()


def build_gen_cert_command(ext_file: str, result_crt: str):
    from_main_dir = lambda path: CERTS_DIR + '/' + path

    return f'openssl x509 -req -sha256 -days 1024 ' \
           f'-in {from_main_dir(CSR_FILENAME)} ' \
           f'-CA {from_main_dir(ROOT_CRTNAME)} ' \
           f'-CAkey {from_main_dir(ROOT_KEYNAME)} -CAcreateserial ' \
           f'-extfile {ext_file} ' \
           f'-out {result_crt} &'


def generate_cert(hostname: str):
    with cert_gen_lock:
        hosts_cert_dir = CERTS_DIR + '/' + GENERATED_CERTS_DIR
        source_ext_file = CERTS_DIR + '/' + EXT_FILENAME
        result_crt = hosts_cert_dir + '/' + hostname + '/' + CRT_FILENAME

        for subdir, dirs, files in os.walk(hosts_cert_dir):
            if hostname in dirs:
                return result_crt
            else:
                break

        os.mkdir(f'{hosts_cert_dir}/{hostname}')

        dest_ext_file = hosts_cert_dir + '/' + hostname + '/' + EXT_FILENAME
        copyfile(source_ext_file, dest_ext_file)

        with open(dest_ext_file, 'a') as f:
            f.write(f'\nDNS.1 = {hostname} \n')

        cmd = build_gen_cert_command(dest_ext_file, result_crt)
        if os.system(cmd):
            raise RuntimeError('cert generation failed')

        return result_crt

