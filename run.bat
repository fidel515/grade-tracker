@echo off
set "DATABASE_URL=postgresql://grade_tracker_db_user:A3VnD674FKEL7G84yX366LdHuHMF2SvG@dpg-d6mloaf5r7bs73ch41p0-a.oregon-postgres.render.com/grade_tracker_db"
echo Starting GradeVault...
python app.py
pause
