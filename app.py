import streamlit as st
from phishing_scanner import analyze_url, vt_scan_url, get_whois_info, capture_screenshot

st.set_page_config(page_title="Phishing Link Scanner", layout="centered")
st.title("🔐 Phishing Link Scanner")

url = st.text_input("Enter a URL to scan")

if st.button("Scan URL"):
    if not url.startswith("http"):
        url = "http://" + url

    with st.spinner("Analyzing..."):
        results, score, verdict = analyze_url(url)
        vt_result = vt_scan_url(url)
        whois_info = get_whois_info(url)
        screenshot_file = capture_screenshot(url)

    st.subheader("🧪 Heuristic Results")
    for k, v in results.items():
        st.write(f"- **{k}**: {'✅ No' if not v else '🚩 Yes'}")

    st.markdown(f"**📊 Phishing Score**: {score}/6")
    st.markdown(f"**⚠️ Verdict**: {verdict}")

    st.subheader("🔍 VirusTotal")
    st.write(vt_result)

    st.subheader("📑 WHOIS Info")
    st.write(whois_info)

    st.subheader("🖼️ Screenshot")
    if isinstance(screenshot_file, str) and screenshot_file.endswith(".png"):
        st.image(screenshot_file, caption="Website Preview", use_column_width=True)
    else:
        st.error(screenshot_file)
