import json


class JsonRpcNostrestParams:
    endpoint: str
    body: {}
    query: {}

    def __init__(self, endpoint: str, body: dict = None, query: dict = None):
        self.endpoint = endpoint
        self.body = body
        self.query = query

    def __iter__(self):
        yield from {
            "endpoint": self.endpoint,
            "body": self.body,
            "query": self.query
        }.items()

    def __str__(self):
        return json.dumps(del_none(dict(self)), ensure_ascii=False)

    def __repr__(self):
        return self.__str__()

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(json_str):
        try:
            json_dct = json.loads(json_str)

            endpoint = json_dct['endpoint'] if 'endpoint' in json_dct.keys() else None
            body = json_dct['body'] if 'body' in json_dct.keys() else None
            query = json_dct['query'] if 'query' in json_dct.keys() else None

            return JsonRpcNostrestParams(endpoint, body, query)
        except:
            return None


class JsonRpcRequest:
    jsonrpc: str
    id: str
    method: str
    params: JsonRpcNostrestParams

    def __init__(self, id: str, method: str, params: JsonRpcNostrestParams = None):
        self.jsonrpc = '2.0'
        self.id = id
        self.method = method
        self.params = params

    def __iter__(self):
        yield from {
            "jsonrpc": self.jsonrpc,
            "id": self.id,
            "method": self.method,
            "params": self.params
        }.items()

    def __str__(self):
        a = dict(self)
        if 'params' in a.keys() and a['params'] is not None:
            a['params'] = dict(a['params'])
        return json.dumps(del_none(a), ensure_ascii=False)

    def __repr__(self):
        return self.__str__()

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(json_str):
        try:
            json_dct = json.loads(json_str)
            id = json_dct['id']
            method = json_dct['method']
            params = None
            if 'params' in json_dct.keys():
                endpoint = json_dct['params']['endpoint'] if 'endpoint' in json_dct['params'].keys() else None
                body = json_dct['params']['body'] if 'body' in json_dct['params'].keys() else None
                query = json_dct['params']['query'] if 'query' in json_dct['params'].keys() else None
                params = JsonRpcNostrestParams(endpoint, body, query)

            return JsonRpcRequest(id, method, params)
        except:
            return None


class JsonRpcError:
    code: int
    message: str

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message

    def __iter__(self):
        yield from {
            "code": self.code,
            "message": self.message
        }.items()

    def __str__(self):
        return json.dumps(del_none(dict(self)), ensure_ascii=False)

    def __repr__(self):
        return self.__str__()

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(json_str):
        try:
            json_dct = json.loads(json_str)
            code = json_dct['code']
            message = json_dct['message']
            return JsonRpcError(code, message)
        except:
            return None


class JsonRpcResponse:
    jsonrpc: str = '2.0'
    id: str
    error: JsonRpcError
    result: {}

    def __init__(self, id: str, result: {} = None, error: JsonRpcError = None):
        self.jsonrpc = '2.0'
        self.id = id
        self.result = result
        self.error = error

    def __iter__(self):
        yield from {
            "jsonrpc": self.jsonrpc,
            "id": self.id,
            "result": self.result,
            "error": self.error
        }.items()

    def __str__(self):
        a = dict(self)
        if 'error' in a.keys() and a['error'] is not None:
            a['error'] = dict(a['error'])
        return json.dumps(del_none(a), ensure_ascii=False)

    def __repr__(self):
        return self.__str__()

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(json_str):
        try:
            json_dct = json.loads(json_str)
            id = json_dct['id']
            result = json_dct['result']
            error = None
            if 'error' in json_dct.keys() and 'code' in json_dct['error'].keys() and 'message' in json_dct[
                'error'].keys():
                error = JsonRpcError(json_dct['error']['code'], json_dct['error']['message'])
            return JsonRpcResponse(id, result, error)
        except:
            return None


def del_none(d):
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d  # For convenience
