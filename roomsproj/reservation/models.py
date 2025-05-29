from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
import os

def validate_image_size(value):
    """Validate that the file size is not greater than 2MB"""
    max_size = 2 * 1024 * 1024  # 2MB in bytes
    if value.size > max_size:
        raise ValidationError('Image file size cannot exceed 2MB.')

def user_photo_path(instance, filename):
    """Generate a unique path for user photos"""
    # Get the file extension
    ext = filename.split('.')[-1]
    # Create a new filename
    new_filename = f"{instance.user.username}_{int(timezone.now().timestamp())}.{ext}"
    # Return the upload path
    return os.path.join('user_photos', new_filename)

class Room(models.Model):
    FACILITY_TYPES = [
        ('function_hall', 'Function Hall'),
        ('pe_room', 'PE Room'),
        ('conference_room', 'Conference Room'),
        ('classroom', 'Classroom'),
        ('other', 'Other'),
    ]
    
    name = models.CharField(max_length=100)
    facility_type = models.CharField(max_length=20, choices=FACILITY_TYPES, default='other')
    capacity = models.PositiveIntegerField()
    location = models.CharField(max_length=200)
    amenities = models.TextField(blank=True)
    operating_hours_start = models.TimeField(default='08:00:00')
    operating_hours_end = models.TimeField(default='17:00:00')
    max_booking_duration = models.DurationField(default='1:00:00', help_text="Maximum duration for a single booking")
    booking_rules = models.TextField(blank=True, help_text="Special rules or restrictions for booking")
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_facility_type_display()})"
    
    def is_available(self, start_time, end_time):
        """Check if facility is available during the given time slot"""
        # Check if time is within operating hours
        start_hour = start_time.time()
        end_hour = end_time.time()
        if not (self.operating_hours_start <= start_hour <= self.operating_hours_end and 
                self.operating_hours_start <= end_hour <= self.operating_hours_end):
            return False
        
        # Check if duration is within max booking duration
        duration = end_time - start_time
        if duration > self.max_booking_duration:
            return False
        
        # Check for overlapping reservations
        overlapping = self.reservations.filter(
            start_time__lt=end_time,
            end_time__gt=start_time,
            status='approved'
        ).exists()
        
        return not overlapping

class Admin(models.Model):
    ADMIN_LEVELS = [
        ('super', 'Super Admin'),
        ('department', 'Department Admin'),
        ('facility', 'Facility Admin'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    department = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    position = models.CharField(max_length=100)
    admin_id = models.CharField(max_length=20, unique=True)
    admin_level = models.CharField(max_length=20, choices=ADMIN_LEVELS, default='facility')
    managed_facilities = models.ManyToManyField(Room, blank=True, related_name='managing_admins')
    is_super_admin = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.username} - {self.position}"
    
    def can_approve_reservation(self, reservation):
        """Check if admin has authority to approve this reservation"""
        if self.is_super_admin:
            return True
        if self.admin_level == 'department' and reservation.user.profile.department == self.department:
            return True
        if self.admin_level == 'facility' and reservation.room in self.managed_facilities.all():
            return True
        return False

    def get_all_users(self, **filters):
        """
        Get all registered users based on admin's permission level and optional filters
        
        Args:
            **filters: Optional filters like department, role, etc.
            
        Returns:
            QuerySet of User objects
        """
        users = User.objects.filter(is_active=True)
        
        # Super admin can see all users
        if self.is_super_admin:
            pass
        # Department admin can only see users in their department
        elif self.admin_level == 'department':
            users = users.filter(profile__department=self.department)
        # Facility admin can see users who have made reservations for their facilities
        elif self.admin_level == 'facility':
            facility_users = Reservation.objects.filter(
                room__in=self.managed_facilities.all()
            ).values_list('user', flat=True).distinct()
            users = users.filter(id__in=facility_users)
            
        # Apply additional filters if provided
        if 'department' in filters:
            users = users.filter(profile__department=filters['department'])
        if 'role' in filters:
            users = users.filter(profile__role=filters['role'])
        if 'search' in filters:
            search_term = filters['search']
            users = users.filter(
                models.Q(username__icontains=search_term) |
                models.Q(first_name__icontains=search_term) |
                models.Q(last_name__icontains=search_term) |
                models.Q(email__icontains=search_term)
            )
            
        return users.distinct()

    def get_user_details(self, user_id):
        """
        Get detailed information about a specific user
        
        Args:
            user_id: ID of the user to get details for
            
        Returns:
            User object with related profile or None if not authorized
        """
        try:
            user = User.objects.select_related('profile').get(id=user_id)
            
            # Check if admin has permission to view this user
            if self.is_super_admin:
                return user
            elif self.admin_level == 'department' and user.profile.department == self.department:
                return user
            elif self.admin_level == 'facility':
                # Check if user has any reservations in admin's facilities
                has_reservation = Reservation.objects.filter(
                    user=user,
                    room__in=self.managed_facilities.all()
                ).exists()
                if has_reservation:
                    return user
            return None
        except User.DoesNotExist:
            return None

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('faculty', 'Faculty Member'),
        ('student', 'Student'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    department = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    student_id = models.CharField(max_length=20, blank=True, null=True)
    faculty_id = models.CharField(max_length=20, blank=True, null=True)
    photo = models.ImageField(
        upload_to=user_photo_path,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp']),
            validate_image_size
        ],
        blank=True,
        null=True,
        help_text="User profile photo. Only JPG, JPEG, PNG, and WebP files less than 2MB are allowed."
    )
    
    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    def is_faculty(self):
        return self.role == 'faculty'
    
    def is_student(self):
        return self.role == 'student'

class Reservation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
    ]
    
    PURPOSE_CHOICES = [
        ('class', 'Class'),
        ('meeting', 'Meeting'),
        ('event', 'Event'),
        ('practice', 'Practice'),
        ('other', 'Other'),
    ]
    
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='reservations')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reservations')
    title = models.CharField(max_length=100)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default='meeting')
    description = models.TextField(blank=True, default="")
    expected_attendees = models.PositiveIntegerField(default=1)
    equipment_needed = models.TextField(blank=True, help_text="List any equipment or setup needed", default="")
    special_requirements = models.TextField(blank=True, help_text="Any special requirements or arrangements", default="")
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_reservations')
    rejection_reason = models.TextField(blank=True, help_text="Reason for rejection if applicable", default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.title} - {self.room.name} ({self.start_time.strftime('%Y-%m-%d %H:%M')})"
    
    def is_active(self):
        now = timezone.now()
        return self.status == 'approved' and self.start_time <= now <= self.end_time
    
    def clean(self):
        """Validate reservation"""
        if self.start_time >= self.end_time:
            raise ValidationError("End time must be after start time")
        
        if not self.room.is_available(self.start_time, self.end_time):
            raise ValidationError("Facility is not available during the selected time slot")
        
        # Additional validation for students
        if self.user.profile.is_student():
            # Students might have restrictions on booking duration or purpose
            duration = self.end_time - self.start_time
            if duration > timedelta(hours=2):  # Example: 2-hour limit for students
                raise ValidationError("Students can only book facilities for up to 2 hours")
