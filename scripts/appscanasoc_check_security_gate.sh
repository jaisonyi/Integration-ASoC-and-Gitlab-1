#!/bin/bash

# ASoC API 인증 정보
# asocApiKeyId='xxxxxxxxxxxxx'
# asocApiKeySecret='xxxxxxxxxxxxx'
# serviceUrl='xxxxxxxxxxxxx'

# 보안 게이트 정책 - 각 심각도 수준별 허용 임계값 설정 (GitLab CI/CD에서 환경변수로 설정 가능)
# maxCriticalAllowed=100
# maxHighAllowed=200
# maxMediumAllowed=300
# maxLowAllowed=500
# maxTotalAllowed=1000

scanId=$(cat scanId.txt)

# ASoC 로그인 및 토큰 획득
asocToken=$(curl -k -s -X POST --header 'Content-Type:application/json' --header 'Accept:application/json' -d '{"KeyId":"'"$asocApiKeyId"'","KeySecret":"'"$asocApiKeySecret"'"}' "https://$serviceUrl/api/v4/Account/ApiKeyLogin" | grep -oP '(?<="Token":\ ")[^"]*')

if [ -z "$asocToken" ]; then
    echo "❌ Authentication failed: Could not retrieve ASoC token."
    exit 1
fi

# 스캔 기술 유형 확인
scanTech=$(cat scanTech.txt)
if [[ $scanTech == 'Sast' ]]; then
    curl -k -s -X GET "https://$serviceUrl/api/v4/Scans/Sast/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
elif [[ $scanTech == 'Dast' ]]; then
    curl -k -s -X GET "https://$serviceUrl/api/v4/Scans/Dast/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
elif [[ $scanTech == 'Sca' ]]; then
    curl -k -s -X GET "https://$serviceUrl/api/v4/Scans/Sca/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
else
    echo "❌ Scan technology not identified."
    exit 1
fi

# JSON 데이터에서 취약점 개수 추출
criticalIssues=$(jq -r '.LatestExecution.NCriticalIssues' scanResult.txt)
highIssues=$(jq -r '.LatestExecution.NHighIssues' scanResult.txt)
mediumIssues=$(jq -r '.LatestExecution.NMediumIssues' scanResult.txt)
lowIssues=$(jq -r '.LatestExecution.NLowIssues' scanResult.txt)
totalIssues=$(jq -r '.LatestExecution.NIssuesFound' scanResult.txt)

# 결과 출력
echo "🔎 Scan Result: Critical: $criticalIssues, High: $highIssues, Medium: $mediumIssues, Low: $lowIssues, Total: $totalIssues"

# 보안 정책 확인 및 빌드 차단
if [[ "$criticalIssues" -gt "$maxCriticalAllowed" ]]; then
    echo "❌ Security Gate Failed: Critical issues exceeded the limit ($maxCriticalAllowed)."
    exit 1
fi

if [[ "$highIssues" -gt "$maxHighAllowed" ]]; then
    echo "❌ Security Gate Failed: High issues exceeded the limit ($maxHighAllowed)."
    exit 1
fi

if [[ "$mediumIssues" -gt "$maxMediumAllowed" ]]; then
    echo "❌ Security Gate Failed: Medium issues exceeded the limit ($maxMediumAllowed)."
    exit 1
fi

if [[ "$lowIssues" -gt "$maxLowAllowed" ]]; then
    echo "❌ Security Gate Failed: Low issues exceeded the limit ($maxLowAllowed)."
    exit 1
fi

if [[ "$totalIssues" -gt "$maxTotalAllowed" ]]; then
    echo "❌ Security Gate Failed: Total issues exceeded the limit ($maxTotalAllowed)."
    exit 1
fi

echo "✅ Security Gate Passed: All issues are within the allowed limits."

# 로그아웃
curl -k -s -X 'GET' "https://$serviceUrl/api/v4/Account/Logout" -H 'accept: */*' -H "Authorization: Bearer $asocToken"
