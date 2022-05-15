class BaseException(Exception):
    def __init__(self, message) -> None:
        self.message = message
    
    def __str__(self) -> str:
        return self.message

class SEQNumError(BaseException):
    pass

class SEQSaveError(BaseException):
    pass

class SEQLoadError(BaseException):
    pass