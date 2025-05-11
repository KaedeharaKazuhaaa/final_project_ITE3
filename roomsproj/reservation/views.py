from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from .models import Room, UserProfile, Reservation, Admin
from .utils import generate_token, verify_token, get_token_from_request
from .rate_limiter import rate_limit
import json

# Utility to parse JSON

def parse_json(request):
    try:
        return json.loads(request.body)
    except json.JSONDecodeError:
        return None

def token_required(view_func):
    """Decorator to require valid JWT token for protected views"""
    def wrapper(request, *args, **kwargs):
        token = get_token_from_request(request)
        if not token:
            return JsonResponse({'error': 'Token is missing'}, status=401)
        
        user = verify_token(token)
        if not user:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)
        
        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper

# Authentication Views
@csrf_exempt
@rate_limit(requests=5, period=60)  # Limit to 5 registration attempts per minute
def register(request):
    if request.method == 'POST':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            # Validate required fields
            required_fields = ['username', 'email', 'password', 'role', 'department']
            for field in required_fields:
                if field not in data:
                    return JsonResponse({'error': f'Missing required field: {field}'}, status=400)
            
            # Check if username or email already exists
            if User.objects.filter(username=data['username']).exists():
                return JsonResponse({'error': 'Username already exists'}, status=400)
            if User.objects.filter(email=data['email']).exists():
                return JsonResponse({'error': 'Email already exists'}, status=400)
            
            # Create user
            user = User.objects.create(
                username=data['username'],
                email=data['email'],
                password=make_password(data['password']),
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', '')
            )
            
            # Create profile based on role
            if data['role'] == 'admin':
                if 'admin_id' not in data:
                    return JsonResponse({'error': 'admin_id is required for admin registration'}, status=400)
                if 'position' not in data:
                    return JsonResponse({'error': 'position is required for admin registration'}, status=400)
                
                profile = Admin.objects.create(
                    user=user,
                    department=data['department'],
                    phone_number=data.get('phone_number', ''),
                    position=data['position'],
                    admin_id=data['admin_id'],
                    is_super_admin=data.get('is_super_admin', False)
                )
            else:
                profile = UserProfile.objects.create(
                    user=user,
                    department=data['department'],
                    phone_number=data.get('phone_number', ''),
                    role=data['role'],
                    student_id=data.get('student_id') if data['role'] == 'student' else None,
                    faculty_id=data.get('faculty_id') if data['role'] == 'faculty' else None
                )
            
            return JsonResponse({
                'message': 'User registered successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': 'admin' if isinstance(profile, Admin) else profile.role,
                    'department': profile.department
                }
            }, status=201)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@rate_limit(requests=10, period=60)  # Limit to 10 login attempts per minute
def login_view(request):
    if request.method == 'POST':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({'error': 'Username and password are required'}, status=400)
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            login(request, user)
            token = generate_token(user)
            
            # Determine user role and get profile
            try:
                admin_profile = user.admin_profile
                role = 'admin'
                profile = admin_profile
            except Admin.DoesNotExist:
                try:
                    user_profile = user.profile
                    role = user_profile.role
                    profile = user_profile
                except UserProfile.DoesNotExist:
                    return JsonResponse({'error': 'User profile not found'}, status=404)
            
            return JsonResponse({
                'message': 'Login successful',
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    'department': profile.department
                }
            })
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'message': 'Logout successful'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def get_user_info(request):
    if request.method == 'GET':
        user = request.user
        try:
            admin_profile = user.admin_profile
            role = 'admin'
            profile = admin_profile
            is_super_admin = profile.is_super_admin
            position = profile.position
            admin_id = profile.admin_id
        except Admin.DoesNotExist:
            try:
                user_profile = user.profile
                role = user_profile.role
                profile = user_profile
                is_super_admin = None
                position = None
                admin_id = None
            except UserProfile.DoesNotExist:
                return JsonResponse({'error': 'User profile not found'}, status=404)
        
        response_data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': role,
                'department': profile.department,
                'phone_number': profile.phone_number,
            }
        }
        
        if role == 'admin':
            response_data['user'].update({
                'is_super_admin': is_super_admin,
                'position': position,
                'admin_id': admin_id
            })
        elif role == 'student':
            response_data['user']['student_id'] = profile.student_id
        elif role == 'faculty':
            response_data['user']['faculty_id'] = profile.faculty_id
        
        return JsonResponse(response_data)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Room Views
@csrf_exempt
@rate_limit(requests=20, period=60)  # Limit to 20 requests per minute
def room_list(request):
    if request.method == 'GET':
        rooms = list(Room.objects.values())
        return JsonResponse(rooms, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            room = Room.objects.create(**data)
            return JsonResponse({'id': room.id, 'message': 'Room created'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def room_detail(request, pk):
    try:
        room = Room.objects.get(pk=pk)
    except Room.DoesNotExist:
        return JsonResponse({'error': 'Room not found'}, status=404)

    if request.method == 'GET':
        return JsonResponse({'id': room.id, 'name': room.name})  # Add other fields as needed
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            for key, value in data.items():
                setattr(room, key, value)
            room.save()
            return JsonResponse({'message': 'Room updated'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    elif request.method == 'DELETE':
        room.delete()
        return JsonResponse({'message': 'Room deleted'})
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

# UserProfile Views
@csrf_exempt
def profile_list(request):
    if request.method == 'GET':
        profiles = UserProfile.objects.all()
        data = [{
            'id': profile.id,
            'user': {
                'id': profile.user.id,
                'username': profile.user.username,
                'email': profile.user.email
            },
            'department': profile.department,
            'phone_number': profile.phone_number,
            'role': profile.role
        } for profile in profiles]
        return JsonResponse({'profiles': data})
    
    elif request.method == 'POST':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            user = User.objects.get(id=data.get('user_id'))
            profile = UserProfile.objects.create(
                user=user,
                department=data.get('department'),
                phone_number=data.get('phone_number', ''),
                role=data.get('role')
            )
            return JsonResponse({
                'id': profile.id,
                'user': {
                    'id': profile.user.id,
                    'username': profile.user.username,
                    'email': profile.user.email
                },
                'department': profile.department,
                'phone_number': profile.phone_number,
                'role': profile.role
            }, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def profile_detail(request, profile_id):
    try:
        profile = UserProfile.objects.get(id=profile_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Profile not found'}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            'id': profile.id,
            'user': {
                'id': profile.user.id,
                'username': profile.user.username,
                'email': profile.user.email
            },
            'department': profile.department,
            'phone_number': profile.phone_number,
            'role': profile.role
        })
    
    elif request.method == 'PUT':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            profile.department = data.get('department', profile.department)
            profile.phone_number = data.get('phone_number', profile.phone_number)
            profile.role = data.get('role', profile.role)
            profile.save()
            return JsonResponse({
                'id': profile.id,
                'user': {
                    'id': profile.user.id,
                    'username': profile.user.username,
                    'email': profile.user.email
                },
                'department': profile.department,
                'phone_number': profile.phone_number,
                'role': profile.role
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    elif request.method == 'DELETE':
        profile.delete()
        return JsonResponse({'message': 'Profile deleted successfully'})

# Admin Views
@csrf_exempt
@token_required
def admin_list(request):
    if request.method == 'GET':
        # Only super admins can list all admins
        try:
            if not request.user.admin_profile.is_super_admin:
                return JsonResponse({'error': 'Only super admins can view all admins'}, status=403)
        except Admin.DoesNotExist:
            return JsonResponse({'error': 'Admin access required'}, status=403)
        
        admins = Admin.objects.all()
        data = [{
            'id': admin.id,
            'user': {
                'id': admin.user.id,
                'username': admin.user.username,
                'email': admin.user.email
            },
            'department': admin.department,
            'phone_number': admin.phone_number,
            'position': admin.position,
            'admin_id': admin.admin_id,
            'is_super_admin': admin.is_super_admin
        } for admin in admins]
        return JsonResponse({'admins': data})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def admin_detail(request, admin_id):
    try:
        admin = Admin.objects.get(id=admin_id)
    except Admin.DoesNotExist:
        return JsonResponse({'error': 'Admin not found'}, status=404)

    # Check if user is super admin or the admin being viewed
    try:
        if not request.user.admin_profile.is_super_admin and request.user.admin_profile.id != admin.id:
            return JsonResponse({'error': 'Insufficient permissions'}, status=403)
    except Admin.DoesNotExist:
        return JsonResponse({'error': 'Admin access required'}, status=403)

    if request.method == 'GET':
        return JsonResponse({
            'id': admin.id,
            'user': {
                'id': admin.user.id,
                'username': admin.user.username,
                'email': admin.user.email
            },
            'department': admin.department,
            'phone_number': admin.phone_number,
            'position': admin.position,
            'admin_id': admin.admin_id,
            'is_super_admin': admin.is_super_admin
        })
    
    elif request.method == 'PUT':
        # Only super admins can update other admins
        if not request.user.admin_profile.is_super_admin and request.user.admin_profile.id != admin.id:
            return JsonResponse({'error': 'Only super admins can update other admins'}, status=403)
        
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            admin.department = data.get('department', admin.department)
            admin.phone_number = data.get('phone_number', admin.phone_number)
            admin.position = data.get('position', admin.position)
            # Only super admins can change is_super_admin
            if request.user.admin_profile.is_super_admin:
                admin.is_super_admin = data.get('is_super_admin', admin.is_super_admin)
            admin.save()
            
            return JsonResponse({
                'id': admin.id,
                'user': {
                    'id': admin.user.id,
                    'username': admin.user.username,
                    'email': admin.user.email
                },
                'department': admin.department,
                'phone_number': admin.phone_number,
                'position': admin.position,
                'admin_id': admin.admin_id,
                'is_super_admin': admin.is_super_admin
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    elif request.method == 'DELETE':
        # Only super admins can delete admins
        if not request.user.admin_profile.is_super_admin:
            return JsonResponse({'error': 'Only super admins can delete admins'}, status=403)
        
        admin.delete()
        return JsonResponse({'message': 'Admin deleted successfully'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Reservation Views
@csrf_exempt
@rate_limit(requests=15, period=60)  # Limit to 15 requests per minute
def reservation_list(request):
    if request.method == 'GET':
        reservations = Reservation.objects.all()
        data = [{
            'id': res.id,
            'room': {
                'id': res.room.id,
                'name': res.room.name
            },
            'user': {
                'id': res.user.id,
                'username': res.user.username
            },
            'title': res.title,
            'description': res.description,
            'start_time': res.start_time.isoformat(),
            'end_time': res.end_time.isoformat(),
            'status': res.status,
            'created_at': res.created_at.isoformat(),
            'updated_at': res.updated_at.isoformat()
        } for res in reservations]
        return JsonResponse({'reservations': data})
    
    elif request.method == 'POST':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        try:
            # Only allow faculty or student to make reservations
            user_profile = request.user.profile
            if user_profile.role not in ['faculty', 'student']:
                return JsonResponse({'error': 'Only faculty and students can make reservations.'}, status=403)

            room_id = data.get('room')
            if not room_id:
                return JsonResponse({'error': 'Room ID is required.'}, status=400)
            try:
                room = Room.objects.get(id=room_id)
            except Room.DoesNotExist:
                return JsonResponse({'error': 'Room matching query does not exist.'}, status=400)

            reservation = Reservation.objects.create(
                room=room,
                user=request.user,
                title=data.get('title'),
                purpose=data.get('purpose'),
                description=data.get('description', ''),
                expected_attendees=data.get('expected_attendees', 1),
                equipment_needed=data.get('equipment_needed', ''),
                special_requirements=data.get('special_requirements', ''),
                start_time=data.get('start_time'),
                end_time=data.get('end_time'),
            )
            return JsonResponse({
                'id': reservation.id,
                'message': 'Reservation created successfully'
            }, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def reservation_detail(request, reservation_id):
    try:
        reservation = Reservation.objects.get(id=reservation_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Reservation not found'}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            'id': reservation.id,
            'room': {
                'id': reservation.room.id,
                'name': reservation.room.name
            },
            'user': {
                'id': reservation.user.id,
                'username': reservation.user.username
            },
            'title': reservation.title,
            'description': reservation.description,
            'start_time': reservation.start_time.isoformat(),
            'end_time': reservation.end_time.isoformat(),
            'status': reservation.status,
            'created_at': reservation.created_at.isoformat(),
            'updated_at': reservation.updated_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            if data.get('start_time') and data.get('end_time'):
                if data['start_time'] >= data['end_time']:
                    return JsonResponse({'error': 'End time must be after start time'}, status=400)
                reservation.start_time = data['start_time']
                reservation.end_time = data['end_time']
            
            if data.get('room_id'):
                reservation.room = Room.objects.get(id=data['room_id'])
            
            reservation.title = data.get('title', reservation.title)
            reservation.description = data.get('description', reservation.description)
            reservation.save()
            
            return JsonResponse({
                'id': reservation.id,
                'room': {
                    'id': reservation.room.id,
                    'name': reservation.room.name
                },
                'user': {
                    'id': reservation.user.id,
                    'username': reservation.user.username
                },
                'title': reservation.title,
                'description': reservation.description,
                'start_time': reservation.start_time.isoformat(),
                'end_time': reservation.end_time.isoformat(),
                'status': reservation.status,
                'created_at': reservation.created_at.isoformat(),
                'updated_at': reservation.updated_at.isoformat()
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    elif request.method == 'DELETE':
        reservation.delete()
        return JsonResponse({'message': 'Reservation deleted successfully'})
