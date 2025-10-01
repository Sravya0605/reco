package main

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	//findUser("faseeha0720")
	//dir("vnrvjiet.ac.in")
	//Dns("vnrvjiet.ac.in")
	//vhost("vnrvjiet.ac.in")
	//whoIs("vnrvjiet.ac.in")
	//nmap()
	a := app.New()
	w := a.NewWindow("Reco")
	w.Resize(fyne.NewSize(500, 600))

	op := widget.NewMultiLineEntry()
	op.SetMinRowsVisible(20)          // set minimum visible rows to increase height (default is smaller)
	op.Resize(fyne.NewSize(480, 500)) // explicitly set size (width x height) in pixels
	op.Wrapping = fyne.TextWrapWord   // better text wrapping for readability
	op.Hide()

	ip1 := widget.NewEntry()
	ip1.SetPlaceHolder("Enter user name")
	ip1.Hide()

	ip2 := widget.NewEntry()
	ip2.SetPlaceHolder("Enter domain name: vnrvjiet.ac.in or example.com")
	ip2.Hide()

	// Find User button functionality
	go1 := widget.NewButton("Go", func() {
		user := ip1.Text
		if user == "" {
			op.SetText("⚠ Please enter a username")
			op.Show()
			return
		}
		op.SetText("Searching...")
		op.Show()

		go func() {
			arr := findUser(user)
			text := strings.Join(arr, "\n")
			fyne.CurrentApp().Driver().DoFromGoroutine(func() {
				op.SetText(text)
				op.Show()
			}, true)
		}()
	})
	go1.Hide()

	// Website details button functionality
	go2 := widget.NewButton("Go", func() {
		domain := ip2.Text
		if domain == "" {
			op.SetText("⚠ Please enter a domain name")
			op.Show()
			return
		}

		op.SetText("Scanning, please wait...")
		op.Show()

		go func() {
			var wg sync.WaitGroup
			results := make(chan string, 4)

			// Run Whois
			wg.Add(1)
			go func() {
				defer wg.Done()
				lines, err := whoIs(domain)
				if err != nil {
					results <- "WHOIS error: " + err.Error()
				} else {
					results <- "WHOIS results:\n" + strings.Join(lines, "\n")
				}
			}()

			// Run DNS
			wg.Add(1)
			go func() {
				defer wg.Done()
				subs, err := Dns(domain)
				if err != nil {
					results <- "DNS error: " + err.Error()
				} else if len(subs) == 0 {
					results <- "No subdomains found."
				} else {
					results <- "DNS enumeration:\n" + strings.Join(subs, "\n")
				}
			}()

			// Run Dir
			wg.Add(1)
			go func() {
				defer wg.Done()
				arr := dir(domain)
				if len(arr) == 0 {
					results <- "No directories found."
				} else {
					results <- "Directory scan:\n" + strings.Join(arr, "\n")
				}
			}()

			// Run Vhost
			wg.Add(1)
			go func() {
				defer wg.Done()
				hosts, err := vhost(domain)
				if err != nil {
					results <- "VHOST error: " + err.Error()
				} else if len(hosts) == 0 {
					results <- "No virtual hosts found."
				} else {
					results <- "VHOST results:\n" + strings.Join(hosts, "\n")
				}
			}()

			// Wait for all
			go func() {
				wg.Wait()
				close(results)
			}()

			// Collect results as they finish (non-blocking UI updates)
			var final strings.Builder
			for r := range results {
				final.WriteString(r + "\n\n")
			}

			fyne.CurrentApp().Driver().DoFromGoroutine(func() {
				op.SetText(final.String())
				op.Show()
			}, true)
		}()
	})
	go2.Hide()

	// Main buttons for choosing search type
	btn1 := widget.NewButton("Find User", func() {
		ip1.Show()
		go1.Show()
		ip2.Hide()
		go2.Hide()
		op.Hide()
	})

	btn2 := widget.NewButton("Website details", func() {
		ip2.Show()
		go2.Show()
		ip1.Hide()
		go1.Hide()
		op.Hide()
	})

	w.SetContent(container.NewVBox(
		btn1,
		btn2,
		ip1,
		ip2,
		go1,
		go2,
		op,
	))

	w.ShowAndRun()
}
