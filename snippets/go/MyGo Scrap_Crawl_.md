# MyGo Scrap_Crawl_

- Directory: go
- File: MyGo Scrap_Crawl_

## Templates

### crawl goquery get links

```go
// "github.com/PuerkitoBio/goquery"

// extractLinks extracts the data-href attributes from the buttons with the specified class.
// button has classes: button-as-link get-code-btn
func extractLinks(page string) []string {
	// Use the goquery package to parse the HTML page
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(page))
	if err != nil {
		log.Fatalln("Error parsing HTML:", err)
	}

	// Create a slice to store the links
	var links []string

	// Find all buttons with the specified class and extract their data-href attributes
	doc.Find("button.button-as-link.get-code-btn").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("data-href"); exists {
			links = append(links, href)
		}
	})

	return links
}
```

### crawl goquery nested example

```go
/*

// "github.com/PuerkitoBio/goquery"

<ul id="stitch-list">
    <li class="dropdown">
        <span class="category category_toggle">E-Commerce</span>
        <ul class="child_list">
            <li><a href="https://codestitch.app/app/dashboard/catalog/sections/100">All <span class="cat-options">(23)</span></a></li>
            <li><a href="https://codestitch.app/app/dashboard/catalog/232">Collections <span class="cat-options">(11)</span></a></li>
        </ul>
    </li>
    <li class="dropdown">
        <span class="category category_toggle">Buttons</span>
        <ul class="child_list">
            <li><a href="https://codestitch.app/app/dashboard/catalog/sections/22">All <span class="cat-options">(11)</span></a></li>
        </ul>
    </li>
</ul>

*/

doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlFile))
if err != nil {
    log.Fatalln("Error loading HTML:", err)
}

doc.Find("li.dropdown").Each(func(i int, s *goquery.Selection) {
    name := s.Find("span.category_toggle").Text()
    fmt.Println("Element:", name)

    // Find sub-items
    s.Find("ul.child_list a").Each(func(j int, a *goquery.Selection) {
        href, exists := a.Attr("href")
        if exists {
            value := a.Find("span.cat-options").Text()
            fmt.Printf("  - Link: %s | Value: %s\n", href, value)
        }
    })
})
```

### crawl html, scrap example

```go
package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// Structure to hold extracted data
type Item struct {
	Category string
	Links    []LinkInfo
}

type LinkInfo struct {
	Href  string
	Count string
}

func main() {
	htmlContent := `
	<ul id="stitch-list">
		<li class="dropdown ">
			<span class="category category_toggle">E-Commerce</span>
			<ul class="child_list">
				<li><a href="https://codestitch.app/app/dashboard/catalog/sections/100">All <span class="cat-options">(23)</span></a></li>
				<li><a href="https://codestitch.app/app/dashboard/catalog/232">Collections <span class="cat-options">(11)</span></a></li>
			</ul>
		</li>
		<li class="dropdown ">
			<span class="category category_toggle">Buttons</span>
			<ul class="child_list">
				<li><a href="https://codestitch.app/app/dashboard/catalog/sections/22">All <span class="cat-options">(11)</span></a></li>
			</ul>
		</li>
	</ul>`

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		fmt.Println("Error parsing HTML:", err)
		return
	}

	// Extract categories with links dynamically
	data := extractItems(doc, "li", "dropdown ", "span", "category category_toggle", "a", "href", "span", "cat-options")

	// Print extracted data
	for _, item := range data {
		fmt.Println("Category:", item.Category)
		for _, link := range item.Links {
			fmt.Printf("  - URL: %s | Count: %s\n", link.Href, link.Count)
		}
	}
}

// extractItems extracts data based on provided HTML structure details
func extractItems(n *html.Node, parentTag, parentClass, categoryTag, categoryClass, linkTag, linkAttr, countTag, countClass string) []Item {
	var items []Item

	// Traverse and find elements
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == parentTag {
			if getAttribute(n, "class") == parentClass {
				category := extractTextByClass(n, categoryTag, categoryClass)
				links := extractLinks(n, linkTag, linkAttr, countTag, countClass)
				items = append(items, Item{Category: category, Links: links})
			}
		}
		// Recursively check child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(n)
	return items
}

// extractLinks finds all links and their counts within a section
func extractLinks(n *html.Node, linkTag, linkAttr, countTag, countClass string) []LinkInfo {
	var links []LinkInfo

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "ul" {
			for li := c.FirstChild; li != nil; li = li.NextSibling {
				if li.Type == html.ElementNode && li.Data == "li" {
					href, count := extractLinkAndCount(li, linkTag, linkAttr, countTag, countClass)
					if href != "" && count != "" {
						links = append(links, LinkInfo{Href: href, Count: count})
					}
				}
			}
		}
	}

	return links
}

// extractLinkAndCount extracts href and count values
func extractLinkAndCount(n *html.Node, linkTag, linkAttr, countTag, countClass string) (string, string) {
	var href, count string

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == linkTag {
			href = getAttribute(c, linkAttr)
			count = extractTextByClass(c, countTag, countClass)
		}
	}

	return href, count
}

// extractTextByClass finds text within an element of a specific class
func extractTextByClass(n *html.Node, tag, class string) string {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tag {
			if getAttribute(c, "class") == class {
				return getText(c)
			}
		}
	}
	return ""
}

// getAttribute returns the value of a given attribute
func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// getText retrieves all text from a node
func getText(n *html.Node) string {
	if n.Type == html.TextNode {
		return strings.TrimSpace(n.Data)
	}

	var text string
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text += getText(c)
	}
	return strings.TrimSpace(text)
}

```

