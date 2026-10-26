#!/usr/bin/env bash
# Mutation arms: break one safety property in app.js, and prove the named test goes red.
# app.js is backed up with a checksum and restored by an EXIT trap.
#   test/mutation.sh                     # fake-bus arms; exit 0 only if every arm went red and app.js is restored
#   MUT_TARGET=real test/mutation.sh     # the same idea against the real local bus (test/real.pw.ts)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

APP=app.js
BACKUP=$(mktemp -t approve-app) || exit 2
cp "$APP" "$BACKUP"
SUM=$(shasum -a 256 "$APP" | cut -d' ' -f1)
restore() {
  cp "$BACKUP" "$APP"
  local now; now=$(shasum -a 256 "$APP" | cut -d' ' -f1)
  if [ "$now" != "$SUM" ]; then echo "RESTORE FAILED: app.js checksum $now != $SUM (backup at $BACKUP)"; exit 3; fi
  rm -f "$BACKUP"
}
trap restore EXIT

fails=0
# arm NAME GREP FROM TO: replace exactly one occurrence of FROM with TO, run tests matching GREP.
arm() {
  local name=$1 grep=$2 from=$3 to=$4
  cp "$BACKUP" "$APP"
  local n
  n=$(FROM="$from" python3 -c 'import os,sys; print(open(sys.argv[1]).read().count(os.environ["FROM"]))' "$APP")
  if [ "$n" != "1" ]; then echo "ARM $name: pattern found $n times (need 1) -> arm invalid"; fails=$((fails+1)); return; fi
  FROM="$from" TO="$to" python3 -c 'import os,sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace(os.environ["FROM"], os.environ["TO"]))' "$APP"
  local log; log=$(mktemp -t approve-mut)
  if [ "${MUT_TARGET:-fake}" = real ]; then
    E2E_TARGET=real bunx playwright test -g "$grep" --retries=0 >"$log" 2>&1
  else
    bunx playwright test --project=phone -g "$grep" --retries=0 >"$log" 2>&1
  fi
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "ARM $name: RED as required (rc=$rc)"
    grep -E "✘|Error:|Expected|Received" "$log" | head -6 | sed 's/^/    /'
  else
    echo "ARM $name: STILL GREEN -> the test does not guard this property"
    tail -5 "$log" | sed 's/^/    /'
    fails=$((fails+1))
  fi
  rm -f "$log"
}

if [ "${MUT_TARGET:-fake}" = real ]; then
arm "real: xss body via innerHTML" "real bus" \
  'setText(bodyEl, str(a.body));' \
  'bodyEl.innerHTML = str(a.body);'

arm "real: decision binding dropped" "real bus" \
  '{ purpose: "decide", request_id: a.request_id, decision }' \
  '{ purpose: "decide", request_id: a.request_id }'

arm "real: decision binding wrong (always approve)" "real bus" \
  '{ purpose: "decide", request_id: a.request_id, decision }' \
  '{ purpose: "decide", request_id: a.request_id, decision: "approve" }'

arm "real: device binding uses wrong code" "real bus" \
  '{ purpose: "device", user_code: code }' \
  '{ purpose: "device", user_code: "BBBB-BBBB" }'

arm "real: already_decided not handled" "real bus" \
  'if (err instanceof ApiError && err.code === "already_decided") { finish("Already decided"); return; }' \
  ''

arm "real: fetch between tap and passkey prompt" "real bus" \
  'try { cred = prompt(options); }' \
  'try { cred = post(t.path, t.body).then((d) => prompt(d.options)); }'

else
arm "xss: body via innerHTML" "XSS probe" \
  'setText(bodyEl, str(a.body));' \
  'bodyEl.innerHTML = str(a.body);'

arm "decision binding dropped from auth/options" "list, expand, approve one and deny one" \
  '{ purpose: "decide", request_id: a.request_id, decision }' \
  '{ purpose: "decide", request_id: a.request_id }'

arm "decision binding wrong (always approve)" "list, expand, approve one and deny one" \
  '{ purpose: "decide", request_id: a.request_id, decision }' \
  '{ purpose: "decide", request_id: a.request_id, decision: "approve" }'

arm "frame guard removed" "refuses to run inside a frame" \
  'if (window.top !== window.self) {' \
  'if (false) {'

arm "final error keeps dead buttons" "expired code says so" \
  'if (!errs.show(t.error, () => t.load())) stop();' \
  'errs.show(t.error, () => t.load());'

arm "fetch between tap and passkey prompt (WebKit activation)" "starts inside the tap" \
  'try { cred = prompt(options); }' \
  'try { cred = post(t.path, t.body).then((d) => prompt(d.options)); }'

arm "stale prefetched challenge used anyway" "stale prefetched challenge" \
  'Date.now() - this.at > FRESH_MS' \
  'false'

arm "Retry reuses the old options" "register Retry fetches new options" \
  'if (canRetry) t.load(); // a new challenge for the Retry tap' \
  'if (canRetry) { t.options = options; t.state = "ready"; t.at = Date.now(); }'

arm "bad_assertion is final" "bad_assertion offers Retry" \
  '"Passkey not recognized. Try again, or run switchboard passkey add.", retry: true' \
  '"Passkey not recognized. Try again, or run switchboard passkey add.", retry: false'

arm "no (shortened) marker" "marked \\(shortened\\)" \
  'return Array.from(text).length >= BODY_CAP;' \
  'return false;'

arm "device-code warning missing" "device code: Confirm signs the Mac in" \
  'h("p", { class: "warn" }, "Only confirm if you just ran switchboard login and this code matches."),' \
  ''

arm "Have a code? needs exact upper-case input" "Have a code" \
  'const norm = normCode(input.value);' \
  'const norm = input.value.replace("-", "");'

arm "enroll: lookalike confirm skipped" "lookalike needs the extra confirm" \
  '(!lookalikes.length || confirmBox.checked)' \
  'true'

arm "enroll: replace warning missing" "replace warning shows" \
  'h("p", { class: "alert" }, `This replaces the existing agent ${id}; its old key stops working.`)' \
  'null'

arm "enroll: tries_left ignored" "wrong codes count down" \
  '`Wrong code. ${n} ${n === 1 ? "try" : "tries"} left.`' \
  '"Wrong code."'

arm "enroll: third wrong code not final" "wrong codes count down" \
  'if (left === 0) { finish("Denied", "Denied after 3 wrong codes."); return; }' \
  ''

arm "enroll: field via innerHTML" "enrollment fields render as text only" \
  'setText(dd, value);' \
  'dd.innerHTML = value;'

arm "enroll: decision binding dropped" "Deny sends no code" \
  '{ purpose: "enroll_decide", enrollment_id: row.enrollment_id, decision }' \
  '{ purpose: "enroll_decide", enrollment_id: row.enrollment_id }'

arm "enroll: code sent raw" "right code \\(spaces stripped\\)" \
  'snapshot: () => ({ code: codeDigits(codeIn.value),' \
  'snapshot: () => ({ code: codeIn.value,'

arm "enroll: deny sends the code" "Deny sends no code" \
  ': { enrollment_id: row.enrollment_id, decision, assertion };' \
  ': { enrollment_id: row.enrollment_id, decision, code: codeDigits(codeIn.value), assertion };'

arm "enroll: Approve not gated on the code" "lookalike needs the extra confirm" \
  'CODE_OK.test(codeDigits(codeIn.value)) && ' \
  ''

arm "enroll: malformed row still offers Approve" "malformed ID offers only Deny" \
  'const malformed = malformedRow(row);' \
  'const malformed = false;'

arm "enroll: list does not flag a malformed row" "malformed ID offers only Deny" \
  'malformedRow(row) ? h("span", { class: "flag" }, "malformed") : null,' \
  'null,'

arm "enroll: lookalike IDs not monospace" "lookalike IDs are monospace" \
  'const idSpan = (x) => h("span", { class: "id" }, x);' \
  'const idSpan = (x) => x;'

arm "enroll: code read after the prompt" "read at the tap" \
  'code: snap.code, replace, assertion }' \
  'code: codeDigits(codeIn.value), replace, assertion }'

arm "enroll: confirm read after the prompt" "read at the tap" \
  '(!lookalikes.length || snap.confirmed)' \
  '(!lookalikes.length || confirmBox.checked)'

arm "enroll: inputs editable while busy" "read at the tap" \
  'onBusy: (on) => { codeIn.disabled = on; confirmBox.disabled = on || finished; },' \
  'onBusy: () => {},'

arm "enroll: result lost after the view is gone" "after the view is gone" \
  'if (!el.isConnected) app.append(h("p", { class: result.className, role: "status" }, idSpan(id), `: ${message}`));' \
  ''

arm "enroll: wrong code keeps the old challenge" "wrong codes count down" \
  'if (canRetry) t.load(); // a new challenge for the Retry tap' \
  'if (canRetry && errs.retryEl.hidden === false) t.load();'

fi

echo "mutation arms failed to go red: $fails"
[ $fails -eq 0 ]
