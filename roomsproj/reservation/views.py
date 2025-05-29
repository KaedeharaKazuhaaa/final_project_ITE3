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
from django.utils.dateparse import parse_datetime

# Utility to parse JSON

def parse_json(request):
    try:
        return json.loads(request.body)
    except json.JSONDecodeError:
        return None

def handle_uploaded_file(file, max_size_mb=2):
    """Validate uploaded file size and type"""
    if file.size > max_size_mb * 1024 * 1024:
        return False, f"File size exceeds {max_size_mb}MB limit"

    allowed_extensions = ['jpg', 'jpeg', 'png', 'webp']
    ext = file.name.split('.')[-1].lower()
    if ext not in allowed_extensions:
        return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    return True, None

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
@rate_limit(requests=5, period=60)
def user_register(request):
    if request.method == 'POST':
        # Check if the request has files
        if request.FILES:
            # Handle multipart form data
            data = request.POST.dict()
            
            # Process photo if present in the request
            photo = request.FILES.get('photo')
            if photo:
                is_valid, error_msg = handle_uploaded_file(photo)
                if not is_valid:
                    return JsonResponse({'error': error_msg}, status=400)
        else:
            # Handle JSON data
            data = parse_json(request)
            if not data:
                return JsonResponse({'error': 'Invalid JSON or form data'}, status=400)
            photo = None
        
        try:
            # Validate required fields
            required_fields = ['username', 'email', 'password', 'role', 'department']
            for field in required_fields:
                if field not in data:
                    return JsonResponse({'error': f'Missing required field: {field}'}, status=400)
            
            # Ensure role is either student or faculty
            if data['role'] not in ['student', 'faculty']:
                return JsonResponse({'error': 'Role must be either student or faculty'}, status=400)
            
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
            
            profile_data = {
                'user': user,
                'department': data['department'],
                'phone_number': data.get('phone_number', ''),
                'role': data['role'],
                'student_id': data.get('student_id') if data['role'] == 'student' else None,
                'faculty_id': data.get('faculty_id') if data['role'] == 'faculty' else None
            }
            
            # Add photo if it exists
            if photo:
                profile_data['photo'] = photo
            
            profile = UserProfile.objects.create(**profile_data)
            
            return JsonResponse({
                'message': 'User registered successfully',
                'token': generate_token(user)
            }, status=201)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@rate_limit(requests=5, period=60)
def admin_register(request):
    if request.method == 'POST':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            # Validate required fields
            required_fields = ['username', 'email', 'password', 'department', 'position', 'admin_id']
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
            
            # Create admin profile
            admin = Admin.objects.create(
                user=user,
                department=data['department'],
                phone_number=data.get('phone_number', ''),
                position=data['position'],
                admin_id=data['admin_id'],
                is_super_admin=data.get('is_super_admin', False)
            )
            
            return JsonResponse({
                'message': 'Admin registered successfully',
                'token': generate_token(user)
            }, status=201)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@rate_limit(requests=10, period=60)
def user_login(request):
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
            try:
                # Check if user has a UserProfile (not an admin)
                user_profile = user.profile
                login(request, user)
                return JsonResponse({
                    'message': 'Login successful',
                    'token': generate_token(user),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user_profile.role,
                        'department': user_profile.department
                    }
                })
            except UserProfile.DoesNotExist:
                return JsonResponse({'error': 'Invalid user account'}, status=401)
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@rate_limit(requests=10, period=60)
def admin_login(request):
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
            try:
                # Check if user has an Admin profile
                admin_profile = user.admin_profile
                login(request, user)
                return JsonResponse({
                    'message': 'Login successful',
                    'token': generate_token(user),
                    'admin': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'department': admin_profile.department,
                        'position': admin_profile.position,
                        'is_super_admin': admin_profile.is_super_admin
                    }
                })
            except Admin.DoesNotExist:
                return JsonResponse({'error': 'Invalid admin account'}, status=401)
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

@csrf_exempt
@token_required
def update_user(request):
    if request.method == 'PUT':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        user = request.user
        try:
            # Get user profile
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                try:
                    profile = user.admin_profile
                except Admin.DoesNotExist:
                    return JsonResponse({'error': 'User profile not found'}, status=404)

            # Check if updating username
            new_username = data.get('username')
            if new_username and new_username != user.username:
                if User.objects.filter(username=new_username).exists():
                    return JsonResponse({'error': 'Username already exists'}, status=400)
                user.username = new_username

            # Check if updating email
            new_email = data.get('email')
            if new_email and new_email != user.email:
                if User.objects.filter(email=new_email).exists():
                    return JsonResponse({'error': 'Email already exists'}, status=400)
                user.email = new_email

            # Check if updating phone number
            new_phone = data.get('phone_number')
            if new_phone is not None:
                profile.phone_number = new_phone

            # Save changes
            user.save()
            profile.save()

            return JsonResponse({
                'message': 'Profile updated successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'phone_number': profile.phone_number
                }
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
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
        return JsonResponse({
            'id': room.id,
            'name': room.name,
            'facility_type': room.facility_type,
            'capacity': room.capacity,
            'location': room.location,
            'amenities': room.amenities,
            'operating_hours_start': room.operating_hours_start.strftime('%H:%M:%S'),
            'operating_hours_end': room.operating_hours_end.strftime('%H:%M:%S'),
            'max_booking_duration': str(room.max_booking_duration),
            'booking_rules': room.booking_rules,
            'is_active': room.is_active
        })
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
            user_data = data.get('user', {})
            profile_data = {
                'department': data.get('department'),
                'phone_number': data.get('phone_number'),
                'position': data.get('position'),
                'is_super_admin': data.get('is_super_admin')
            }
            
            # Check what's being updated
            is_user_update = any(user_data.get(field) for field in ['username', 'email'])
            is_profile_update = any(profile_data.get(field) is not None for field in profile_data)
            
            # Update user fields if provided
            if user_data:
                new_username = user_data.get('username')
                if new_username and new_username != admin.user.username:
                    if User.objects.filter(username=new_username).exclude(id=admin.user.id).exists():
                        return JsonResponse({'error': 'Username already exists'}, status=400)
                    admin.user.username = new_username

                new_email = user_data.get('email')
                if new_email and new_email != admin.user.email:
                    if User.objects.filter(email=new_email).exclude(id=admin.user.id).exists():
                        return JsonResponse({'error': 'Email already exists'}, status=400)
                    admin.user.email = new_email
                
                admin.user.save()

            # Update admin profile fields
            if is_profile_update:
                if profile_data['department'] is not None:
                    admin.department = profile_data['department']
                if profile_data['phone_number'] is not None:
                    admin.phone_number = profile_data['phone_number']
                if profile_data['position'] is not None:
                    admin.position = profile_data['position']
                # Only super admins can change is_super_admin
                if request.user.admin_profile.is_super_admin and profile_data['is_super_admin'] is not None:
                    admin.is_super_admin = profile_data['is_super_admin']
                
                admin.save()

            # Return appropriate message only
            if is_user_update and not is_profile_update:
                return JsonResponse({'message': 'Username and email updated successfully'})
            elif is_profile_update and not is_user_update:
                return JsonResponse({'message': 'Admin profile updated successfully'})
            else:
                return JsonResponse({'message': 'Admin information updated successfully'})

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
@token_required  # Add this decorator to ensure authentication
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
            # Check if user has a profile
            try:
                user_profile = request.user.profile
            except AttributeError:
                return JsonResponse({'error': 'User profile not found'}, status=403)
                
            # Only allow faculty or student to make reservations
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
@token_required
def pending_reservations(request):
    if request.method == 'GET':
        try:
            # Check if user is admin
            try:
                admin_profile = request.user.admin_profile
            except Admin.DoesNotExist:
                return JsonResponse({'error': 'Admin access required'}, status=403)
            
            # Get pending reservations
            pending = Reservation.objects.filter(status='pending')
            
            # If not super admin, filter based on admin's department
            if not admin_profile.is_super_admin:
                pending = pending.filter(user__profile__department=admin_profile.department)
            
            data = [{
                'id': res.id,
                'room': {
                    'id': res.room.id,
                    'name': res.room.name
                },
                'user': {
                    'id': res.user.id,
                    'username': res.user.username,
                    'department': res.user.profile.department
                },
                'title': res.title,
                'purpose': res.purpose,
                'description': res.description,
                'expected_attendees': res.expected_attendees,
                'equipment_needed': res.equipment_needed,
                'special_requirements': res.special_requirements,
                'start_time': res.start_time.isoformat(),
                'end_time': res.end_time.isoformat(),
                'created_at': res.created_at.isoformat()
            } for res in pending]
            
            return JsonResponse({'pending_reservations': data})
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def reservation_detail(request, reservation_id):
    try:
        reservation = Reservation.objects.get(id=reservation_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Reservation not found'}, status=404)

    if request.method == 'GET':
        response_data = {
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
            'purpose': reservation.purpose,
            'description': reservation.description,
            'expected_attendees': reservation.expected_attendees,
            'equipment_needed': reservation.equipment_needed,
            'special_requirements': reservation.special_requirements,
            'start_time': reservation.start_time.isoformat(),
            'end_time': reservation.end_time.isoformat(),
            'status': reservation.status,
            'created_at': reservation.created_at.isoformat(),
            'updated_at': reservation.updated_at.isoformat()
        }

        # Add rejection reason if status is rejected
        if reservation.status == 'rejected' and hasattr(reservation, 'rejection_reason'):
            response_data['rejection_reason'] = reservation.rejection_reason

        # Add approval info if status is approved
        if reservation.status == 'approved' and hasattr(reservation, 'approved_by'):
            response_data['approved_by'] = {
                'username': reservation.approved_by.username,
                'department': reservation.approved_by.admin_profile.department
            }

        return JsonResponse(response_data)
    
    elif request.method == 'PUT':
        data = parse_json(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        try:
            # Check if user is the owner or an admin
            is_admin = False
            if reservation.user.id != request.user.id:
                # Check if user is admin
                try:
                    admin_profile = request.user.admin_profile
                    is_admin = True
                except Admin.DoesNotExist:
                    return JsonResponse({'error': 'Permission denied'}, status=403)
            
            # Handle admin approval/rejection
            if is_admin and 'status' in data:
                if data['status'] not in ['approved', 'rejected']:
                    return JsonResponse({'error': 'Invalid status. Use "approved" or "rejected"'}, status=400)
                
                reservation.status = data['status']
                reservation.approved_by = request.user
                
                if data['status'] == 'rejected' and 'rejection_reason' in data:
                    reservation.rejection_reason = data['rejection_reason']
                
                reservation.save()
                response_data = {
                    'message': f'Reservation {data["status"]} successfully',
                    'reservation': {
                        'id': reservation.id,
                        'status': reservation.status,
                    }
                }

                # Add rejection reason to response if rejected
                if reservation.status == 'rejected' and hasattr(reservation, 'rejection_reason'):
                    response_data['reservation']['rejection_reason'] = reservation.rejection_reason

                # Add approval info if approved
                if reservation.status == 'approved':
                    response_data['reservation']['approved_by'] = {
                        'username': request.user.username,
                        'department': request.user.admin_profile.department
                    }

                return JsonResponse(response_data)
            
            # Regular update logic for non-admin users
            if data.get('start_time') and data.get('end_time'):
                start_time = parse_datetime(data['start_time'])
                end_time = parse_datetime(data['end_time'])
                
                if not start_time or not end_time:
                    return JsonResponse({'error': 'Invalid datetime format'}, status=400)
                
                if start_time >= end_time:
                    return JsonResponse({'error': 'End time must be after start time'}, status=400)
                
                reservation.start_time = start_time
                reservation.end_time = end_time
            
            # Update room if provided
            if data.get('room'):
                try:
                    room = Room.objects.get(id=data['room'])
                    reservation.room = room
                except Room.DoesNotExist:
                    return JsonResponse({'error': 'Room not found'}, status=400)
            
            # Update other fields
            if 'title' in data:
                reservation.title = data['title']
            if 'purpose' in data:
                reservation.purpose = data['purpose']
            if 'description' in data:
                reservation.description = data['description']
            if 'expected_attendees' in data:
                reservation.expected_attendees = data['expected_attendees']
            if 'equipment_needed' in data:
                reservation.equipment_needed = data['equipment_needed']
            if 'special_requirements' in data:
                reservation.special_requirements = data['special_requirements']
            
            reservation.save()
            
            return JsonResponse({
                'message': 'Reservation updated successfully',
                'reservation': {
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
                }
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    elif request.method == 'DELETE':
        # Check if user is the owner or an admin
        if reservation.user.id != request.user.id:
            # Check if user is admin
            try:
                admin_profile = request.user.admin_profile
            except Admin.DoesNotExist:
                return JsonResponse({'error': 'Permission denied'}, status=403)
                
        reservation.delete()
        return JsonResponse({'message': 'Reservation deleted successfully'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def list_users(request):
    """
    Get list of users based on admin's permissions and filters
    """
    if request.method == 'GET':
        try:
            admin = Admin.objects.get(user=request.user)
        except Admin.DoesNotExist:
            return JsonResponse(
                {"error": "Only administrators can access this endpoint"},
                status=403
            )

        # Get filters from query parameters
        filters = {}
        if request.GET.get('department'):
            filters['department'] = request.GET.get('department')
        if request.GET.get('role'):
            filters['role'] = request.GET.get('role')
        if request.GET.get('search'):
            filters['search'] = request.GET.get('search')

        users = admin.get_all_users(**filters)
        
        # Convert users queryset to JSON-serializable format
        users_data = []
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            }
            
            # Add profile data if it exists
            try:
                profile = user.profile
                user_data['profile'] = {
                    'department': profile.department,
                    'phone_number': profile.phone_number,
                    'role': profile.role,
                    'student_id': profile.student_id,
                    'faculty_id': profile.faculty_id
                }
            except UserProfile.DoesNotExist:
                user_data['profile'] = None
            
            users_data.append(user_data)
        
        return JsonResponse({'users': users_data}, safe=False)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@token_required
def get_user_detail(request, user_id):
    """
    Get detailed information about a specific user or delete the user
    """
    if request.method not in ['GET', 'DELETE']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        admin = Admin.objects.get(user=request.user)
    except Admin.DoesNotExist:
        return JsonResponse(
            {"error": "Only administrators can access this endpoint"},
            status=403
        )

    # Try to get the user
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse(
            {"error": "User not found"},
            status=404
        )

    # Check admin permissions
    if not admin.is_super_admin:
        try:
            # Department admin can only manage users in their department
            if admin.admin_level == 'department':
                if not hasattr(target_user, 'profile') or target_user.profile.department != admin.department:
                    return JsonResponse(
                        {"error": "You don't have permission to manage this user"},
                        status=403
                    )
            # Facility admin can only manage users who have made reservations in their facilities
            elif admin.admin_level == 'facility':
                has_reservation = Reservation.objects.filter(
                    user=target_user,
                    room__in=admin.managed_facilities.all()
                ).exists()
                if not has_reservation:
                    return JsonResponse(
                        {"error": "You don't have permission to manage this user"},
                        status=403
                    )
        except UserProfile.DoesNotExist:
            return JsonResponse(
                {"error": "You don't have permission to manage this user"},
                status=403
            )

    if request.method == 'GET':
        # Convert user details to JSON-serializable format
        user_data = {
            'id': target_user.id,
            'username': target_user.username,
            'email': target_user.email,
            'first_name': target_user.first_name,
            'last_name': target_user.last_name,
            'date_joined': target_user.date_joined.isoformat(),
            'last_login': target_user.last_login.isoformat() if target_user.last_login else None,
        }
        
        # Add profile data if it exists
        try:
            profile = target_user.profile
            user_data['profile'] = {
                'department': profile.department,
                'phone_number': profile.phone_number,
                'role': profile.role,
                'student_id': profile.student_id,
                'faculty_id': profile.faculty_id
            }
        except UserProfile.DoesNotExist:
            user_data['profile'] = None
        
        return JsonResponse(user_data)
    
    elif request.method == 'DELETE':
        # Prevent deleting yourself
        if target_user.id == request.user.id:
            return JsonResponse(
                {"error": "You cannot delete your own account"},
                status=400
            )
        
        # Prevent deleting other admins unless you're a super admin
        try:
            target_user.admin_profile
            if not admin.is_super_admin:
                return JsonResponse(
                    {"error": "Only super admins can delete admin accounts"},
                    status=403
                )
        except Admin.DoesNotExist:
            pass  # Not an admin user, proceed with deletion
        
        # Delete the user
        username = target_user.username
        target_user.delete()
        
        return JsonResponse({
            "message": f"User '{username}' has been deleted successfully"
        })
