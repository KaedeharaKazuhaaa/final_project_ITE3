# ACTIVITY 8: FILE UPLOAD

## Implementation of User Photo Upload

### GitHub Repository
https://github.com/Lou/final_project_ITE3

### Description
For this activity, I have enhanced the user registration model by adding a photo field to allow users to upload profile pictures. The implementation includes file validation to ensure only appropriate image files are accepted.

### Features Implemented

1. **Added `photo` field to `UserProfile` model**
   - Supports only image file types (JPEG, PNG, WebP)
   - Rejects files larger than 2MB
   - Generates unique filenames based on username and timestamp
   - Stores files in a dedicated `user_photos` directory

2. **Updated `register` view to handle file uploads**
   - Added support for multipart/form-data
   - Implemented file validation in a separate utility function
   - Returns proper error messages for invalid file types or sizes

3. **Configured media settings**
   - Added MEDIA_URL and MEDIA_ROOT settings
   - Set up URLs to serve media files during development
   - Added django-cleanup for automatic file management

4. **Updated documentation in README.md**
   - Added information about the photo upload feature
   - Documented the API endpoint for registering with photo upload
   - Added sample responses including success and error scenarios

### API Endpoint Documentation

#### Register with Photo Upload
- **Method**: POST
- **Endpoint URL**: `/api/auth/register/`
- **Content-Type**: `multipart/form-data`
- **Expected Request Body**:
  - `username`: String (required)
  - `email`: String (required)
  - `password`: String (required)
  - `role`: String (required, one of: "student", "faculty")
  - `department`: String (required)
  - `phone_number`: String (optional)
  - `first_name`: String (optional)
  - `last_name`: String (optional)
  - `student_id`: String (required if role is "student")
  - `faculty_id`: String (required if role is "faculty")
  - `photo`: File (optional, only JPEG, PNG, WebP, max 2MB)

- **Sample Response (Success):**
  ```json
  {
    "message": "User registered successfully",
    "user": {
      "id": 1,
      "username": "student1",
      "email": "student1@example.com",
      "role": "student",
      "department": "Computer Science",
      "photo": "http://localhost:8000/media/user_photos/student1_1623412345.jpg"
    }
  }
  ```

- **Sample Response (File Type Error):**
  ```json
  {
    "error": "File type not allowed. Allowed types: jpg, jpeg, png, webp"
  }
  ```

- **Sample Response (File Size Error):**
  ```json
  {
    "error": "File size exceeds 2MB limit"
  }
  ```

### Code Implementation

1. **Model Changes**
   ```python
   def validate_image_size(value):
       """Validate that the file size is not greater than 2MB"""
       max_size = 2 * 1024 * 1024  # 2MB in bytes
       if value.size > max_size:
           raise ValidationError('Image file size cannot exceed 2MB.')

   def user_photo_path(instance, filename):
       """Generate a unique path for user photos"""
       ext = filename.split('.')[-1]
       new_filename = f"{instance.user.username}_{int(timezone.now().timestamp())}.{ext}"
       return os.path.join('user_photos', new_filename)

   class UserProfile(models.Model):
       # ... existing fields ...
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
   ```

2. **View Changes**
   ```python
   def handle_uploaded_file(file, max_size_mb=2):
       """Validate uploaded file size and type"""
       if file.size > max_size_mb * 1024 * 1024:
           return False, f"File size exceeds {max_size_mb}MB limit"

       allowed_extensions = ['jpg', 'jpeg', 'png', 'webp']
       ext = file.name.split('.')[-1].lower()
       if ext not in allowed_extensions:
           return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
       
       return True, None

   @csrf_exempt
   @rate_limit(requests=5, period=60)
   def register(request):
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
           
           # ... rest of registration logic ...
           # Add photo if it exists
           if photo:
               profile_data['photo'] = photo
   ```

### Settings Changes
- Added MEDIA_URL and MEDIA_ROOT to settings.py
- Added django-cleanup to INSTALLED_APPS
- Added media file URL configuration

### Testing the Implementation
For testing the file upload functionality:
1. Start the Django server: `python manage.py runserver`
2. Use a tool like Postman to send a multipart/form-data POST request to `/api/auth/register/`
3. Include a JPEG, PNG, or WebP image file less than 2MB in size with the field name `photo`
4. Make sure all required fields are included in the request
5. Observe the response to verify the photo URL is returned 