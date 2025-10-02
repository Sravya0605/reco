package main

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.NewWithID("reco.app")
	w := a.NewWindow("Reco – Reconnaissance Tool")
	w.Resize(fyne.NewSize(700, 700))

	// Output box
	op := widget.NewMultiLineEntry()
	op.SetMinRowsVisible(25)
	op.Resize(fyne.NewSize(680, 600))
	op.Wrapping = fyne.TextWrapWord
	op.Hide()

	// Input fields
	ip1 := widget.NewEntry()
	ip1.SetPlaceHolder("Enter username (e.g. johndoe)")
	ip1.Hide()

	ip2 := widget.NewEntry()
	ip2.SetPlaceHolder("Enter domain (e.g. example.com)")
	ip2.Hide()

	// Buttons
	go1 := widget.NewButtonWithIcon("Run", theme.ConfirmIcon(), func() {
		user := ip1.Text
		if user == "" {
			op.SetText("Please enter a username")
			op.Show()
			return
		}
		op.SetText("Searching for user info...")
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

	go2 := widget.NewButtonWithIcon("Run Scan", theme.ConfirmIcon(), func() {
		domain := ip2.Text
		if domain == "" {
			op.SetText("Please enter a domain name")
			op.Show()
			return
		}

		op.SetText("Running scans, please wait...\n Feel free to get a coffee, this will take a while")
		op.Show()

		go func() {
			var wg sync.WaitGroup
			results := make(chan string, 11) // buffer for all tools

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

			// Run Email Harvester
			wg.Add(1)
			go func() {
				defer wg.Done()
				emails, err := emailHarvester(domain)
				if err != nil {
					results <- "Email Harvester error: " + err.Error()
				} else if len(emails) == 0 {
					results <- "No emails found."
				} else {
					results <- "Email Harvester:\n" + FormatEmailResults(emails)
				}
			}()

			// Run SSL Scanner
			wg.Add(1)
			go func() {
				defer wg.Done()
				ssl, err := sslScanner(domain)
				if err != nil {
					results <- "SSL Scanner error: " + err.Error()
				} else {
					results <- "SSL Scanner:\n" + strings.Join(ssl, "\n")
				}
			}()

			// Run Technology Detector
			wg.Add(1)
			go func() {
				defer wg.Done()
				techs, err := techDetector(domain)
				if err != nil {
					results <- "Technology Detector error: " + err.Error()
				} else if len(techs) == 0 {
					results <- "No technologies detected."
				} else {
					results <- "Technology Detector:\n" + FormatTechResults(techs)
				}
			}()

			// Run Web Vulnerability Scanner
			wg.Add(1)
			go func() {
				defer wg.Done()
				vulns, err := webVulnScanner(domain)
				if err != nil {
					results <- "Web Vulnerability Scanner error: " + err.Error()
				} else {
					results <- "Web Vulnerability Scanner:\n" + strings.Join(vulns, "\n")
				}
			}()

			// Run Nmap
			wg.Add(1)
			go func() {
				defer wg.Done()
				nmapResults, err := RunNmapScans(domain, false)
				if err != nil {
					results <- "Nmap error: " + err.Error()
				} else {
					results <- "Nmap Results:\n" + nmapResults
				}
			}()

			// Wait for all
			go func() {
				wg.Wait()
				close(results)
			}()

			// Collect results
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

	// Navigation buttons
	btn1 := widget.NewButtonWithIcon("Find User", theme.AccountIcon(), func() {
		ip1.Show()
		go1.Show()
		ip2.Hide()
		go2.Hide()
		op.Hide()
	})

	btn2 := widget.NewButtonWithIcon("Website Details", theme.ComputerIcon(), func() {
		ip2.Show()
		go2.Show()
		ip1.Hide()
		go1.Hide()
		op.Hide()
	})

	// Layout
	w.SetContent(
		container.NewVBox(
			widget.NewLabelWithStyle("Reco – Reconnaissance Tool", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			container.New(layout.NewGridLayout(2), btn1, btn2),
			ip1,
			ip2,
			go1,
			go2,
			widget.NewSeparator(),
		),
	)

	w.ShowAndRun()
}
