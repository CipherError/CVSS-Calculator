from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import json

from ai_engine import analyze_vulnerability
from cvss_calculator import calculate_cvss

app = FastAPI()

templates = Jinja2Templates(directory="templates")


class VulnInput(BaseModel):
    name: str
    description: str



@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
    request=request,
    name="index.html"
)   

@app.post("/analyze")
def analyze(data: VulnInput):

    try:
        ai_result = analyze_vulnerability(
            data.name,
            data.description
        )

        print("AI RAW RESPONSE:")
        print(ai_result)

        parsed = json.loads(ai_result)

        vector = parsed["cvss_vector"]
        cwe = parsed["cwe"]

        score, severity = calculate_cvss(vector)

        return {
            "CVSS Vector": vector,
            "CVSS Score": score,
            "Severity": severity,
            "CWE": cwe
        }

    except Exception as e:

        return {
            "error": str(e),
            "raw_response": ai_result if 'ai_result' in locals() else "No response"
        }