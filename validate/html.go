package validate

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/antchfx/htmlquery"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	htmlDirectiveElements = map[string]string{
		"script-src": "script",
		"img-src":    "img",
		"media-src":  "audio, video, track",
		"frame-src":  "iframe",
		"object-src": "object, embed, applet",
		"style-src":  "style",
	}

	htmlPassiveElements = map[string]bool{
		"img":    true,
		"audio":  true,
		"video":  true,
		"object": true,
	}
)

// ValidatePage checks that an HTML page passes the specified CSP policy.
func ValidatePage(p Policy, page url.URL, html io.Reader) (bool, []Report, error) {
	doc, err := goquery.NewDocumentFromReader(html)
	if err != nil {
		return false, nil, err
	}
	var reports []Report

	for directiveName, elems := range htmlDirectiveElements {
		directive := p.Directive(directiveName)
		var err2 error
		doc.Find(elems).Each(func(i int, s *goquery.Selection) {
			ctx := SourceContext{
				Page:  page,
				Nonce: s.AttrOr("nonce", ""),
			}

			elementName := strings.ToLower(s.Nodes[0].Data)
			passiveContent := htmlPassiveElements[elementName]

			src := s.AttrOr("src", "")
			if len(src) > 0 {
				parsed, err := url.Parse(src)
				if err != nil {
					err2 = err
					return
				}

				ctx.URL = *page.ResolveReference(parsed)
			} else {
				ctx.Body = []byte(s.Text())
				ctx.UnsafeInline = true
			}

			// Upgrade insecure passive content http requests to correctly support
			// mixed content.
			if ctx.Page.Scheme == "https" && ctx.URL.Scheme == "http" && ((passiveContent && !p.BlockAllMixedContent) || p.UpgradeInsecureRequests) {
				ctx.URL.Scheme = "https"
			}

			v, err := directive.Check(p, ctx)
			if err != nil {
				err2 = err
				return
			}
			if !v {
				reports = append(reports, ctx.Report(directiveName, directive))
			}

			if goquery.NodeName(s) == "style" {
				_, reportsCSS, err := ValidateStylesheet(p, page, s.Text())
				if err != nil {
					err2 = err
					return
				}
				reports = append(reports, reportsCSS...)
			}
		})
		if err2 != nil {
			return false, nil, err2
		}
	}

	hrefTypes := map[string]string{
		"base-uri":     "base",
		"style-src":    "link[rel=stylesheet]",
		"prefetch-src": "link[rel=prefetch], link[rel=prerender]",
		"manifest-src": "link[rel=manifest]",
		"img-src":      "link[rel=icon], link[rel=apple-touch-icon]",
	}
	for directiveName, elems := range hrefTypes {
		directive := p.Directive(directiveName)
		var err2 error
		doc.Find(elems).Each(func(i int, s *goquery.Selection) {
			ctx := SourceContext{
				Page:  page,
				Nonce: s.AttrOr("nonce", ""),
			}
			href := s.AttrOr("href", "")
			if len(href) > 0 {
				parsed, err := url.Parse(href)
				if err != nil {
					err2 = err
					return
				}
				ctx.URL = *page.ResolveReference(parsed)
			}

			v, err := directive.Check(p, ctx)
			if err != nil {
				err2 = err
				return
			}
			if !v {
				reports = append(reports, ctx.Report(directiveName, directive))
			}
		})
		if err2 != nil {
			return false, nil, err2
		}
	}

	return len(reports) == 0, reports, nil
}

// retrieves the current CSP setting from a web page
func GetCSPFromWeb(webaddress string) (string, string, *url.URL, error) {
	// create a http client object
	client := &http.Client{Timeout: 5 * time.Second}

	// create a new GET request
	req, err := http.NewRequest("GET", webaddress, nil)
	if err != nil {
		return "", "", nil, errors.New(fmt.Sprintf("Error creating request: %s", err))
	}

	// make the request
	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil, errors.New(fmt.Sprintf("Error making request: %s", err))
	}

	// read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, errors.New(fmt.Sprintf("Error reading response: %s", err))
	}
	// print the response body
	doc, err := htmlquery.Parse(strings.NewReader(string(body)))
	if err != nil {
		log.Errorf("not a valid XPath expression.")
	}
	elements := htmlquery.Find(doc, "//meta[@http-equiv]")
	redirect := false
	redirectUrl := ""
	for _, n := range elements {
		for _, attributes := range n.Attr {
			if attributes.Key == "content" {
				content := strings.Split(attributes.Val, ";")
				for _, value := range content {
					if strings.HasPrefix(value, "url=") {
						redirectUrl = strings.Split(value, "url=")[1]
					}
				}
			}
			if attributes.Key == "http-equiv" && attributes.Val == "refresh" {
				redirect = true
			}
		}
	}
	finalUrl := resp.Request.URL
	if redirect && len(redirectUrl) > 0 {
		parsedRedirectUrl, err := url.Parse(redirectUrl)
		if err != nil {
			log.Errorf("Couln't parse redirect url %s. Error: %v", redirectUrl, err)
			return resp.Header.Get("content-security-policy"), string(body), finalUrl, nil
		}
		absoluteRedirectUrl := req.URL.ResolveReference(parsedRedirectUrl)
		log.Debugf("Fetching data from HTML meta redirect to %s", absoluteRedirectUrl.String())
		return GetCSPFromWeb(absoluteRedirectUrl.String())
	} else {
		log.Infof("Final host: %s", finalUrl.String())
	}

	return resp.Header.Get("content-security-policy"), string(body), finalUrl, nil
}
