class RestResponse:
    error_message: str
    url: str
    body: dict
    status_code: int

    def __init__(self, url: str, status_code: int, body, error_message: str = None):
        self.url = url
        self.status_code = status_code
        self.body = body
        self.error_message = error_message

    def ok(self):
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    def raise_for_status(self):

        http_error_msg = None

        if 400 <= self.status_code < 500:
            http_error_msg = (
                f"{self.status_code} Client Error: {self.error_message} for url: {self.url}"
            )

        elif 500 <= self.status_code < 600:
            http_error_msg = (
                f"{self.status_code} Server Error: {self.error_message} for url: {self.url}"
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def json(self):
        return self.body


class HTTPError(IOError):
    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)
