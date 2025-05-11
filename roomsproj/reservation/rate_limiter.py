from django.http import JsonResponse
import time
from functools import wraps
from django.core.cache import cache

def rate_limit(requests=100, period=60, by_ip=True):
    """
    Rate limiting decorator that restricts the number of requests within a specific timeframe.
    
    Args:
        requests (int): Maximum number of requests allowed within the time period
        period (int): Time period in seconds
        by_ip (bool): Whether to limit by IP address or user ID
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Get the key for rate limiting (IP or user ID)
            if by_ip:
                key = f"ratelimit:{request.META.get('REMOTE_ADDR', '0.0.0.0')}"
            else:
                # If authenticated, use user ID, otherwise IP
                key = f"ratelimit:{request.user.id}" if hasattr(request, 'user') and request.user.is_authenticated else f"ratelimit:{request.META.get('REMOTE_ADDR', '0.0.0.0')}"
            
            # Add prefix to avoid collision with other keys
            key = f"{key}:{view_func.__name__}"
            
            # Get current timestamp
            now = time.time()
            
            # Try to get the request history from cache
            request_history = cache.get(key, [])
            
            # Remove requests older than the time period
            request_history = [timestamp for timestamp in request_history if timestamp > now - period]
            
            # Check if the number of requests exceeds the limit
            if len(request_history) >= requests:
                # Return 429 Too Many Requests
                response = JsonResponse({
                    'error': 'Too many requests',
                    'message': f'Request limit of {requests} per {period} seconds exceeded. Please try again later.',
                }, status=429)
                
                # Add Retry-After header in seconds
                retry_after = int(request_history[0] + period - now) + 1
                response['Retry-After'] = str(retry_after)
                
                return response
            
            # Add current timestamp to history and update cache
            request_history.append(now)
            cache.set(key, request_history, period)
            
            # Process the request
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    
    return decorator 