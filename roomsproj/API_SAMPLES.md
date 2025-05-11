# Room Reservation API Sample Requests and Responses

## Authentication Endpoints

### User Registration

#### Request
```http
POST /api/auth/register/
Content-Type: application/json

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

#### Successful Response (201 Created)
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "faculty1",
    "email": "faculty1@example.com",
    "role": "faculty",
    "department": "Computer Science"
  }
}
```

#### Rate Limit Exceeded Response (429 Too Many Requests)
```json
{
  "error": "Too many requests",
  "message": "Request limit of 5 per 60 seconds exceeded. Please try again later."
}
```
Headers:
```
Retry-After: 45
```

### User Login

#### Request
```http
POST /api/auth/login/
Content-Type: application/json

{
  "username": "faculty1",
  "password": "faculty123"
}
```

#### Successful Response (200 OK)
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "faculty1",
    "email": "faculty1@example.com",
    "role": "faculty",
    "department": "Computer Science"
  }
}
```

#### Rate Limit Exceeded Response (429 Too Many Requests)
```json
{
  "error": "Too many requests",
  "message": "Request limit of 10 per 60 seconds exceeded. Please try again later."
}
```
Headers:
```
Retry-After: 32
```

## Room Endpoints

### List Rooms

#### Request
```http
GET /api/rooms/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Successful Response (200 OK)
```json
[
  {
    "id": 1,
    "name": "Main Function Hall",
    "facility_type": "function_hall",
    "capacity": 200,
    "location": "Main Building, 1st Floor",
    "amenities": "Projector, Sound System",
    "operating_hours_start": "08:00:00",
    "operating_hours_end": "17:00:00",
    "max_booking_duration": "01:00:00",
    "booking_rules": "No food allowed"
  },
  {
    "id": 2,
    "name": "Conference Room A",
    "facility_type": "conference_room",
    "capacity": 30,
    "location": "Admin Building, 2nd Floor",
    "amenities": "Projector, Whiteboard",
    "operating_hours_start": "09:00:00",
    "operating_hours_end": "18:00:00",
    "max_booking_duration": "02:00:00",
    "booking_rules": "Clean after use"
  }
]
```

#### Rate Limit Exceeded Response (429 Too Many Requests)
```json
{
  "error": "Too many requests",
  "message": "Request limit of 20 per 60 seconds exceeded. Please try again later."
}
```
Headers:
```
Retry-After: 18
```

## Reservation Endpoints

### List Reservations

#### Request
```http
GET /api/reservations/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Successful Response (200 OK)
```json
[
  {
    "id": 1,
    "room": {
      "id": 2,
      "name": "Conference Room A"
    },
    "user": {
      "id": 1,
      "username": "faculty1"
    },
    "title": "Department Meeting",
    "purpose": "meeting",
    "description": "Monthly department meeting",
    "expected_attendees": 20,
    "equipment_needed": "Projector",
    "special_requirements": "Coffee service",
    "start_time": "2024-06-01T10:00:00Z",
    "end_time": "2024-06-01T12:00:00Z",
    "status": "pending",
    "created_at": "2024-05-15T14:30:00Z"
  }
]
```

#### Rate Limit Exceeded Response (429 Too Many Requests)
```json
{
  "error": "Too many requests",
  "message": "Request limit of 15 per 60 seconds exceeded. Please try again later."
}
```
Headers:
```
Retry-After: 25
```

### Create Reservation

#### Request
```http
POST /api/reservations/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

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

#### Successful Response (201 Created)
```json
{
  "id": 1,
  "room": {
    "id": 2,
    "name": "Conference Room A"
  },
  "user": {
    "id": 1,
    "username": "faculty1"
  },
  "title": "Department Meeting",
  "purpose": "meeting",
  "description": "Monthly department meeting",
  "expected_attendees": 20,
  "equipment_needed": "Projector",
  "special_requirements": "Coffee service",
  "start_time": "2024-06-01T10:00:00Z",
  "end_time": "2024-06-01T12:00:00Z",
  "status": "pending",
  "created_at": "2024-05-15T14:30:00Z"
}
```

#### Rate Limit Exceeded Response (429 Too Many Requests)
```json
{
  "error": "Too many requests",
  "message": "Request limit of 15 per 60 seconds exceeded. Please try again later."
}
```
Headers:
```
Retry-After: 25
``` 