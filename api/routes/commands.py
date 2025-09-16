# api/routes/commands.py
import subprocess
from fastapi import APIRouter, HTTPException, Query, Body

router = APIRouter()

@router.get("/run")
async def run_command_get(cmd: str = Query(..., description="Command to execute")):
    """
    Execute a backend command via GET.
    Example: /commands/run?cmd=ls
    """
    return await _execute_command(cmd)


@router.post("/run")
async def run_command_post(payload: dict = Body(...)):
    """
    Execute a backend command via POST.
    Example JSON:
    {
        "command": "ls -la"
    }
    """
    cmd = payload.get("command")
    if not cmd:
        raise HTTPException(status_code=400, detail="Missing 'command' field in body")
    return await _execute_command(cmd)


# ------------------------
# Internal helper
# ------------------------
async def _execute_command(command: str):
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=20
        )
        return {
            "status": "success",
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
