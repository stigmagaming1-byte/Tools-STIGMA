# TODO: Fix Data Loss and Add Logout Button

## Issues to Fix:
- User data disappears after logout/login
- Admin-created data not persisting
- Need auto-save/lock data functionality
- Logout button should redirect to index.html

## Implementation Plan:

### Backend Changes:
1. [x] Modify `api/check.py` to save user stats to database when checking cookies
2. [ ] Update `api/auth.py` to load user data properly on login
3. [ ] Add auto-save functionality for user data
4. [ ] Ensure sessions persist across logouts

### Frontend Changes:
1. [ ] Update `public/script.js` to load existing user data on login
2. [ ] Add auto-save for user stats during checking
3. [ ] Ensure logout button redirects to index.html (already implemented)
4. [ ] Add data persistence checks

### Testing:
1. [ ] Test user login/logout data persistence
2. [ ] Test cookie checking data saving
3. [ ] Test logout button functionality
