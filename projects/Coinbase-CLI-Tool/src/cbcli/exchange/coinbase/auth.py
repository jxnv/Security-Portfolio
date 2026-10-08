from coinbase.rest import RESTClient

from cbcli.core.config import Settings, load_cdp_api_key_file


def build_coinbase_rest_client(settings: Settings) -> RESTClient:
    api_key, api_secret = load_cdp_api_key_file(settings.cdp_api_key_path)
    return RESTClient(api_key=api_key, api_secret=api_secret)