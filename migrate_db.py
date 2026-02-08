"""
Database migration script to add solved_count and streak columns to User table
"""
import sqlite3
import sys

def migrate_database():
    try:
        # Connect to the database
        conn = sqlite3.connect('focustalk.db')
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Add solved_count column if it doesn't exist
        if 'solved_count' not in columns:
            print("Adding solved_count column...")
            cursor.execute("ALTER TABLE users ADD COLUMN solved_count INTEGER DEFAULT 0 NOT NULL")
            print("✅ solved_count column added")
        else:
            print("solved_count column already exists")
        
        # Add streak column if it doesn't exist
        if 'streak' not in columns:
            print("Adding streak column...")
            cursor.execute("ALTER TABLE users ADD COLUMN streak INTEGER DEFAULT 0 NOT NULL")
            print("✅ streak column added")
        else:
            print("streak column already exists")
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("\n✅ Database migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    migrate_database()
