# Save Point: Successful Deck List Submission with Discord Login

**Date:** 2025-12-05

## Milestone Achieved
- Deck submission now requires Discord login.
- Decks are saved to `decks.json` with correct structure:
  - No `deckContents` field.
  - Starting Army cards only in the `StartingArmy` section.
  - Card type counts included at the top of each type list.
- Event submissions include Discord username, display name, and warlord.
- Backend securely updates GitHub via server-side token.
- All environment variables are managed via Railway dashboard.
- No duplicate code or redeclaration errors remain.

## Next Steps
- Test deck download and event list updates in production.
- Continue with further feature requests or bug fixes as needed.

---
This save point marks a stable, production-ready backend and deck submission flow.
