package cmd

import (
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/miekg/dns"
    "github.com/fatih/color"
    "github.com/juju/ansiterm"
)

// printRecords prints the DNS records to the terminal.
func printRecords(domainName string, messages []*dns.Msg) {
    w := ansiterm.NewTabWriter(os.Stdout, 8, 8, 4, ' ', 0)
    w.SetColorCapable(true)

    domainColored := color.HiBlueString(domainName)

    for _, msg := range messages {
        for _, answer := range msg.Answer {
            queryType := dns.TypeToString[answer.Header().Rrtype]
            formattedTTL := color.HiMagentaString(formatTTL(answer.Header().Ttl))

            switch rec := answer.(type) {
            case *dns.A:
                printARecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.AAAA:
                printAAAARecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.CNAME:
                printCNAMERecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.MX:
                printMXRecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.TXT:
                printTXTRecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.NS:
                printNSRecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.SOA:
                printSOARecord(w, queryType, domainColored, formattedTTL, rec)

            case *dns.PTR:
                printPTRRecord(w, queryType, domainColored, formattedTTL, rec)

            default:
                fmt.Fprintf(os.Stderr, "Unknown record type: %s\n", queryType)
            }
        }
    }

    w.Flush()
}

func printARecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.A) {
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.A.String()))
}

func printAAAARecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.AAAA) {
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.AAAA.String()))
}

func printCNAMERecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.CNAME) {
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Target))
}

func printMXRecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.MX) {
    preference := color.HiRedString(strconv.FormatUint(uint64(rec.Preference), 10))
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s %s\n", color.HiYellowString(queryType), domain, ttl, preference, color.HiWhiteString(rec.Mx))
}

func printTXTRecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.TXT) {
    txtJoined := strings.Join(rec.Txt, " ")
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(txtJoined))
}

func printNSRecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.NS) {
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Ns))
}

func printSOARecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.SOA) {
    primaryNameServer := color.HiRedString(rec.Ns)
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s %s\n", color.HiYellowString(queryType), domain, ttl, primaryNameServer, rec.Mbox)
}

func printPTRRecord(w *ansiterm.TabWriter, queryType, domain, ttl string, rec *dns.PTR) {
    fmt.Fprintf(w, "%s\t%s.\t%s\t%s\n", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Ptr))
}

// formatTTL converts TTL to a more readable format (hours, minutes, seconds).
func formatTTL(ttl uint32) string {
    duration := time.Duration(ttl) * time.Second
    hours := int(duration.Hours())
    minutes := int(duration.Minutes()) % 60
    seconds := int(duration.Seconds()) % 60

    if hours > 0 {
        return fmt.Sprintf("%02dh%02dm%02ds", hours, minutes, seconds)
    } else if minutes > 0 {
        return fmt.Sprintf("%02dm%02ds", minutes, seconds)
    }
    return fmt.Sprintf("%02ds", seconds)
}

