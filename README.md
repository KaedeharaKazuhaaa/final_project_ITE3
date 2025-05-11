# ROOMS: Reservation and Organization of Occupied Meeting Spaces

A meeting room reservation system that allows users to book rooms, manage reservations, and organize their meeting spaces.

## Features

- User authentication and authorization
- Room management (create, update, view, delete)
- Reservation management (create, update, view, delete)
- User profiles with departmental information
- Reservation approval workflow
- User profile photo upload (supports JPEG, PNG, WebP, with 2MB size limit)

## Installation

1. Clone this repository
2. Create a virtual environment: `python -m venv rooms`
3. Activate the virtual environment:
   - Windows: `rooms\Scripts\activate`
   - Linux/Mac: `source rooms/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run migrations: `cd roomsproj && python manage.py migrate`
6. Create a superuser: `python manage.py createsuperuser`
7. Start the server: `python manage.py runserver`

## API Documentation

### Authentication

#### Register (User/Admin)
- **POST** `/api/auth/register/`
- **Method**: POST
- **Content-Type**: `application/json` or `multipart/form-data` (for photo uploads)
- **Body (User - JSON):**
  ```json
  {
    "username": "faculty1",
    "email": "faculty1@example.com",
    "password": "faculty123",
    "role": "faculty",
    "department": "Computer Science",
    "phone_number": "1234567890",
    "first_name": "John",
    "last_name": "Doe",
    "faculty_id": "FAC001"
  }
  ```
- **Body (User with Photo - multipart/form-data):**
  - `username`: "student1"
  - `email`: "student1@example.com"
  - `password`: "student123"
  - `role`: "student"
  - `department`: "Computer Science"
  - `phone_number`: "1234567890"
  - `first_name`: "Jane" 
  - `last_name`: "Doe"
  - `student_id`: "STU001"
  - `photo`: [image file - JPEG, PNG, WebP only, max 2MB]
  
- **Body (Admin):**
  ```json
  {
    "username": "admin1",
    "email": "admin1@example.com",
    "password": "adminpass123",
    "role": "admin",
    "department": "Administration",
    "phone_number": "1234567890",
    "first_name": "Alice",
    "last_name": "Admin",
    "admin_id": "ADM001",
    "position": "Facility Manager",
    "is_super_admin": true
  }
  ```
- **Response (Success - 201):**
  ```json
  {
    "message": "User registered successfully",
    "user": {
      "id": 1,
      "username": "student1",
      "email": "student1@example.com",
      "role": "student",
      "department": "Computer Science",
      "photo": "http://example.com/media/user_photos/student1_1623412345.jpg"
    }
  }
  ```
- **Response (Error - 400):**
  ```json
  {
    "error": "File size exceeds 2MB limit"
  }
  ```
  Or
  ```json
  {
    "error": "File type not allowed. Allowed types: jpg, jpeg, png, webp"
  }
  ```

#### Login
- **POST** `/api/auth/login/`
- **Body:**
  ```json
  {
    "username": "faculty1",
    "password": "faculty123"
  }
  ```
- **Response:**  Returns a JWT token to use in the `Authorization: Bearer <token>` header.

---

### Room Endpoints

#### Create Room
- **POST** `/api/rooms/`
- **Body:**
  ```json
  {
    "name": "Main Function Hall",
    "facility_type": "function_hall",
    "capacity": 200,
    "location": "Main Building, 1st Floor",
    "amenities": "Projector, Sound System",
    "operating_hours_start": "08:00:00",
    "operating_hours_end": "17:00:00",
    "max_booking_duration": "01:00:00",
    "booking_rules": "No food allowed"
  }
  ```

#### List Rooms
- **GET** `/api/rooms/`

#### Get Room Detail
- **GET** `/api/rooms/<id>/`

#### Update Room
- **PUT** `/api/rooms/<id>/`
- **Body:** (any updatable fields)

#### Partial Update Room
- **PATCH** `/api/rooms/<id>/`
- **Body:** (any updatable fields)

#### Delete Room
- **DELETE** `/api/rooms/<id>/`

---

### Reservation Endpoints

#### Create Reservation
- **POST** `/api/reservations/`
- **Body:**
  ```json
  {
    "room": 2,
    "title": "Department Meeting",
    "purpose": "meeting",
    "description": "Monthly department meeting",
    "expected_attendees": 20,
    "equipment_needed": "Projector",
    "special_requirements": "Coffee service",
    "start_time": "2024-06-01T10:00:00Z",
    "end_time": "2024-06-01T12:00:00Z"
  }
  ```

#### List Reservations
- **GET** `/api/reservations/`

#### Get Reservation Detail
- **GET** `/api/reservations/<id>/`

#### Update Reservation
- **PUT** `/api/reservations/<id>/`
- **Body:** (any updatable fields)

#### Partial Update Reservation
- **PATCH** `/api/reservations/<id>/`
- **Body:** (any updatable fields)

#### Delete Reservation
- **DELETE** `/api/reservations/<id>/`

---

### Authentication
- All endpoints (except register/login) require the `Authorization: Bearer <token>` header.

## Error Responses

All endpoints may return the following error responses:

- **400 Bad Request**
  ```json
  {
    "error": "Error message"
  }
  ```

- **401 Unauthorized**
  ```json
  {
    "error": "Token is missing"
  }
  ```
  or
  ```json
  {
    "error": "Invalid or expired token"
  }
  ```

- **404 Not Found**
  ```json
  {
    "error": "Resource not found"
  }
  ```

- **405 Method Not Allowed**
  ```json
  {
    "error": "Method not allowed"
  }
  ```

- **429 Too Many Requests**
  ```json
  {
    "error": "Too many requests",
    "message": "Request limit of X per Y seconds exceeded. Please try again later."
  }
  ```
  This response will include a `Retry-After` header indicating the number of seconds to wait before making another request.

## Rate Limiting

The API implements rate limiting to prevent abuse and ensure stability:

| Endpoint | Rate Limit |
|----------|------------|
| User Registration | 5 requests per minute |
| Login | 10 requests per minute |
| Room List | 20 requests per minute |
| Reservations | 15 requests per minute |

When a rate limit is exceeded, the API will return a 429 Too Many Requests response with a Retry-After header.

## Authentication

The API uses JWT (JSON Web Token) for authentication. To access protected endpoints:

1. Login using the `/api/login/` endpoint to get a token
2. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <token>
   ```
3. The token expires after 24 hours

## Role-Based Access Control

The system has three user roles:

1. **Admin**
   - Can manage all rooms
   - Can view and manage all user profiles
   - Can approve/reject reservations
   - Full access to all features

2. **Faculty**
   - Can view available rooms
   - Can create and manage their own reservations
   - Can view their own profile
   - Cannot manage other users' reservations

3. **Student**
   - Can view available rooms
   - Can create and manage their own reservations
   - Can view their own profile
   - Cannot manage other users' reservations

## API Endpoints

### Rooms

#### List/Create Rooms
- **URL**: `/rooms/`
- **Method**: `GET` or `POST`
- **Headers**: 
  - `Content-Type: application/json`
- **GET Response**:
```json
{
    "rooms": [
        {
            "id": 1,
            "name": "Conference Room A",
            "capacity": 20,
            "location": "Floor 1",
            "amenities": "Projector, Whiteboard",
            "is_active": true
        }
    ]
}
```
- **POST Request Body**:
```json
{
    "name": "Conference Room B",
    "capacity": 15,
    "location": "Floor 2",
    "amenities": "TV Screen",
    "is_active": true
}
```

#### Get/Update/Delete Room
- **URL**: `/rooms/<room_id>/`
- **Method**: `GET`, `PUT`, or `DELETE`
- **Headers**: 
  - `Content-Type: application/json`
- **PUT Request Body**:
```json
{
    "name": "Updated Room Name",
    "capacity": 25,
    "location": "Floor 3",
    "amenities": "Updated amenities",
    "is_active": true
}
```

### User Profiles

#### List/Create Profiles
- **URL**: `/profiles/`
- **Method**: `GET` or `POST`
- **Headers**: 
  - `Content-Type: application/json`
- **GET Response**:
```json
{
    "profiles": [
        {
            "id": 1,
            "user": {
                "id": 1,
                "username": "john_doe",
                "email": "john@example.com"
            },
            "department": "IT",
            "phone_number": "1234567890",
            "role": "Developer"
        }
    ]
}
```
- **POST Request Body**:
```json
{
    "user_id": 1,
    "department": "HR",
    "phone_number": "9876543210",
    "role": "Manager"
}
```

#### Get/Update/Delete Profile
- **URL**: `/profiles/<profile_id>/`
- **Method**: `GET`, `PUT`, or `DELETE`
- **Headers**: 
  - `Content-Type: application/json`
- **PUT Request Body**:
```json
{
    "department": "Updated Department",
    "phone_number": "5555555555",
    "role": "Updated Role"
}
```

### Reservations

#### List/Create Reservations
- **URL**: `/reservations/`
- **Method**: `GET` or `POST`
- **Headers**: 
  - `Content-Type: application/json`
- **GET Response**:
```json
{
    "reservations": [
        {
            "id": 1,
            "room": {
                "id": 1,
                "name": "Conference Room A"
            },
            "user": {
                "id": 1,
                "username": "john_doe"
            },
            "title": "Team Meeting",
            "description": "Weekly team sync",
            "start_time": "2024-03-20T10:00:00Z",
            "end_time": "2024-03-20T11:00:00Z",
            "status": "pending",
            "created_at": "2024-03-19T15:00:00Z",
            "updated_at": "2024-03-19T15:00:00Z"
        }
    ]
}
```
- **POST Request Body**:
```json
{
    "room_id": 1,
    "title": "New Meeting",
    "description": "Project kickoff",
    "start_time": "2024-03-21T14:00:00Z",
    "end_time": "2024-03-21T15:00:00Z"
}
```

#### Get/Update/Delete Reservation
- **URL**: `/reservations/<reservation_id>/`
- **Method**: `GET`, `PUT`, or `DELETE`
- **Headers**: 
  - `Content-Type: application/json`
- **PUT Request Body**:
```json
{
    "room_id": 2,
    "title": "Updated Meeting",
    "description": "Updated description",
    "start_time": "2024-03-22T10:00:00Z",
    "end_time": "2024-03-22T11:00:00Z"
}
```

## Error Responses

All endpoints may return the following error responses:

- **400 Bad Request**: Invalid request data
```json
{
    "error": "Error message"
}
```

- **401 Unauthorized**: Authentication required
```json
{
    "error": "Authentication credentials were not provided"
}
```

- **403 Forbidden**: Insufficient permissions
```json
{
    "error": "Admin access required"
}
```

- **404 Not Found**: Resource not found
```json
{
    "error": "Resource not found"
}
``` 