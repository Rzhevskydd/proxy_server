import os
from multiprocessing import Lock
from shutil import copyfile

from proxy.common.constant import CERTS_MAIN_DIRNAME, CERTS_DIRNAME, EXT_FILENAME, CSR_FILENAME, ROOT_CRTNAME, \
    ROOT_KEYNAME, CRT_FILENAME

cert_gen_lock = Lock()


def build_gen_cert_command(ext_file: str, result_crt: str):
    from_main_dir = lambda path: CERTS_MAIN_DIRNAME + '/' + path

    return f'openssl x509 -req -sha256 -days 1024 ' \
           f'-in {from_main_dir(CSR_FILENAME)} ' \
           f'-CA {from_main_dir(ROOT_CRTNAME)} ' \
           f'-CAkey {from_main_dir(ROOT_KEYNAME)} -CAcreateserial ' \
           f'-extfile {ext_file} ' \
           f'-out {result_crt} &'


def generate_cert(hostname: str):
    with cert_gen_lock:
        hosts_cert_dir = CERTS_MAIN_DIRNAME + '/' + CERTS_DIRNAME
        source_ext_file = CERTS_MAIN_DIRNAME + '/' + EXT_FILENAME

        # TODO check existing dir
        os.mkdir(f'{hosts_cert_dir}/{hostname}')

        dest_ext_file = hosts_cert_dir + '/' + hostname + '/' + EXT_FILENAME
        copyfile(source_ext_file, dest_ext_file)

        with open(dest_ext_file, 'a') as f:
            f.write(f'\nDNS.1 = {hostname} \n')

        result_crt = hosts_cert_dir + '/' + hostname + '/' + CRT_FILENAME

        cmd = build_gen_cert_command(dest_ext_file, result_crt)
        code = os.system(cmd)

        return result_crt

