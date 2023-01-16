import json
import unittest

from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse, JsonRpcError, JsonRpcNostrestParams


class TestJsonRpcIsh(unittest.TestCase):
    def test_serialize_nostrest_params(self):
        json_str = '{"endpoint": "/foo", "body": {}}'
        par = JsonRpcNostrestParams.from_json(json_str)
        ser = par.to_json()
        assert json_str == ser

    def test_serialize_request(self):
        json_str = '{"jsonrpc": "2.0", "id": "id", "method": "method", "params": {"endpoint": "/foo"}}'
        req = JsonRpcRequest.from_json(json_str)
        ser = req.to_json()
        assert json_str == ser

    def test_serialize_error(self):
        json_str = '{"code": 42, "message": "This is fine!"}'
        err = JsonRpcError.from_json(json_str)
        ser = err.to_json()
        assert json_str == ser

    def test_serialize_response(self):
        json_str = '{"jsonrpc": "2.0", "id": "id", "result": {"foo": "bar"}}'
        res = JsonRpcResponse.from_json(json_str)
        ser = res.to_json()
        assert json_str == ser



if __name__ == '__main__':
    unittest.main()
