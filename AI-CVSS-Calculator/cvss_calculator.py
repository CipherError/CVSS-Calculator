from cvss import CVSS3

def calculate_cvss(vector):

    cvss = CVSS3(vector)

    score = cvss.scores()[0]

    if score == 0:
        severity = "None"
    elif score <= 3.9:
        severity = "Low"
    elif score <= 6.9:
        severity = "Medium"
    elif score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    return score, f"{severity} ({score})"