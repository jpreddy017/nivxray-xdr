"""Translate non-swallowable decoder refusals only at the HTTP boundary."""
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse
from .resource_limits import DecodeLimitExceeded, budget

def response(exc):
    return JSONResponse(status_code=exc.status_code, content={'detail':{'code':exc.code, 'message':str(exc)}})

class DecoderRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def guarded(request):
            try:
                with budget():
                    return await handler(request)
            except DecodeLimitExceeded as exc:
                return response(exc)
        return guarded

class DecoderResourceMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            with budget():
                await self.app(scope, receive, send)
        except DecodeLimitExceeded as exc:
            if scope['type'] != 'http':
                raise
            await response(exc)(scope, receive, send)
