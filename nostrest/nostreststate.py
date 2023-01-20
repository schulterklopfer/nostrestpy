import json
from nostrest.del_none import del_none


class NostrestState:
    latest_event_at: int

    def __init__(self, latest_event_at: int):
        self.latest_event_at = latest_event_at

    def __iter__(self):
        yield from {
            "latest_event_at": self.latest_event_at,
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

    def save(self, state_file: str):
        try:
            f = open(state_file, "w")
            f.write(self.to_json())
            f.close()
        except:
            return

    @staticmethod
    def from_json(json_str):
        try:
            json_dct = json.loads(json_str)
            latest_event_at = json_dct['latest_event_at']
            return NostrestState(latest_event_at)
        except:
            return NostrestState(0)

    @staticmethod
    def from_file(state_file):
        try:
            f = open(state_file, "r")
            json_str = f.read()
            f.close()
            return NostrestState.from_json(json_str)
        except:
            return NostrestState(0)
