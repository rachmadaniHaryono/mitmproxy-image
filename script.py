"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261

dev pkg:
- flake8==3.6.0
- pdbpp==0.9.2

required pkg:
- mitmproxy==4.0.4
"""
import hashlib
import shutil
import tempfile

from mitmproxy.script import concurrent
from mitmproxy import ctx, http


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def write_file_async(flow_item, ext):
    h = hashlib.sha256()
    block = 128*1024
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_fname = f.name
            with open(temp_fname, 'wb', buffering=0) as f:
                for b in chunks(flow_item.response.content, block):
                    h.update(b)
                    f.write(b)
            sha256_csum = h.hexdigest()
            new_fname = '{}.{}'.format(sha256_csum, ext)
            shutil.move(temp_fname, new_fname)
        ctx.log.info('DONE:{}'.format(new_fname))
    except Exception as e:
        ctx.log.error('url: {}'.format(flow_item.request.pretty_url))
        ctx.log.error('{}:{}'.format(type(e), e))


@concurrent
def response(flow: http.HTTPFlow) -> None:
    if 'content-type' in flow.response.headers:
        content_type = flow.response.headers['content-type']
        if content_type.startswith('image'):
            # check in database
            in_databse = False
            if not in_databse:
                ext = content_type.split('/')[1].split(';')[0]
                invalid_exts = ['svg+xml', 'x-icon', 'gif']
                if ext not in invalid_exts:
                    write_file_async(flow, ext)

                    # send to server
                    req_url = flow.request.pretty_url  # NOQA
                    #  sha256_csum
                    #  ext
