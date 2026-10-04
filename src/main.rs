use regex::Regex;
use reqwest::Error;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::{thread, time};
use thirtyfour::prelude::*;
use tokio;
use chrono::Utc;

#[derive(Debug, Deserialize)]
struct IpInfo {
    ip: String,
    hostname: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    loc: Option<String>,
    org: Option<String>,
    postal: Option<String>,
    timezone: Option<String>,
    readme: Option<String>,
}

impl IpInfo {
    fn to_hash_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("IP".to_string(), self.ip.clone());
        if let Some(ref hostname) = self.hostname {
            map.insert("Hostname".to_string(), hostname.clone());
        }
        if let Some(ref city) = self.city {
            map.insert("City".to_string(), city.clone());
        }
        if let Some(ref region) = self.region {
            map.insert("Region".to_string(), region.clone());
        }
        if let Some(ref country) = self.country {
            map.insert("Country".to_string(), country.clone());
        }
        if let Some(ref loc) = self.loc {
            map.insert("Location".to_string(), loc.clone());
        }
        if let Some(ref org) = self.org {
            map.insert("Organization".to_string(), org.clone());
        }
        if let Some(ref postal) = self.postal {
            map.insert("Postal Code".to_string(), postal.clone());
        }
        if let Some(ref timezone) = self.timezone {
            map.insert("Timezone".to_string(), timezone.clone());
        }
        map
    }
}

// Function to pause execution for a given number of seconds
fn pause_with_delay(seconds: u64) {
    let pause_time = time::Duration::from_secs(seconds);
    thread::sleep(pause_time);
}

// Function to validate domain names using a regex pattern
fn is_valid_domain(domain: &str) -> bool {
    let domain_regex = Regex::new(r"^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})$").unwrap();
    domain_regex.is_match(domain)
}

// Function to validate IP addresses
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok()
}

// Function to sanitize user input to ensure it is a valid domain or IP address
fn sanitize_input(input: &str) -> Option<String> {
    let trimmed_input = input.trim();
    if is_valid_domain(trimmed_input) || is_valid_ip(trimmed_input) {
        Some(trimmed_input.to_string())
    } else {
        None
    }
}

// Function to extract text from an element found by XPath
async fn get_element_text(driver: &WebDriver, xpath: &str) -> WebDriverResult<Option<String>> {
    match driver.find_element(By::XPath(xpath)).await {
        Ok(element) => {
            let text = element.text().await?;
            Ok(Some(text))
        }
        Err(_) => Ok(None),
    }
}

// Function to scrape location data
async fn scrape_location_data(driver: &WebDriver) -> WebDriverResult<Option<String>> {
    let xpath = "//div[@id='location-data-wrapper']//span[@class='flag-icon flag-icon-us']/parent::td";
    get_element_text(driver, xpath).await
}

// Function to scrape owner details
async fn scrape_owner_details(driver: &WebDriver) -> WebDriverResult<HashMap<String, String>> {
    let mut data = HashMap::new();

    let sections = vec![
        ("IP ADDRESS", "//td[text()='IP Address']/following-sibling::td"),
        ("FWD/REV DNS MATCH", "//td[text()='FWD/REV DNS MATCH']/following-sibling::td"),
        ("HOSTNAME", "//td[text()='Hostname']/following-sibling::td"),
        ("DOMAIN", "//td[text()='Domain']/following-sibling::td"),
        ("NETWORK OWNER", "//td[text()='Network Owner']/following-sibling::td"),
    ];

    for (key, xpath) in sections {
        if let Some(text) = get_element_text(driver, xpath).await? {
            data.insert(key.to_string(), text);
        }
    }

    Ok(data)
}

// Function to scrape reputation details
async fn scrape_reputation_details(driver: &WebDriver) -> WebDriverResult<HashMap<String, String>> {
    let mut data = HashMap::new();

    let sections = vec![
        ("SENDER IP REPUTATION", "//td[text()='Sender IP Reputation']/following-sibling::td"),
        ("WEB REPUTATION", "//td[text()='Web Reputation']/following-sibling::td"),
    ];

    for (key, xpath) in sections {
        if let Some(text) = get_element_text(driver, xpath).await? {
            data.insert(key.to_string(), text);
        }
    }

    Ok(data)
}

// Function to scrape email volume data
async fn scrape_email_volume_data(driver: &WebDriver) -> WebDriverResult<HashMap<String, String>> {
    let mut data = HashMap::new();

    let sections = vec![
        ("EMAIL VOLUME LAST DAY", "//td[text()='Email Volume Last Day']/following-sibling::td"),
        ("EMAIL VOLUME LAST MONTH", "//td[text()='Email Volume Last Month']/following-sibling::td"),
        ("VOLUME CHANGE", "//td[text()='Volume Change']/following-sibling::td"),
        ("SPAM LEVEL", "//td[text()='Spam Level']/following-sibling::td"),
    ];

    for (key, xpath) in sections {
        if let Some(text) = get_element_text(driver, xpath).await? {
            data.insert(key.to_string(), text);
        }
    }

    Ok(data)
}

// Function to scrape block lists
async fn scrape_block_lists(driver: &WebDriver) -> WebDriverResult<HashMap<String, String>> {
    let mut data = HashMap::new();

    let sections = vec![
        ("BL.SPAMCOP.NET", "//td[@class='chart-data-label col_left']/a[contains(@href, 'spamcop.net')]/../following-sibling::td"),
        ("CBL.ABUSEAT.ORG", "//td[@class='chart-data-label col_left']/a[contains(@href, 'abuseat.org')]/../following-sibling::td"),
        ("PBL.SPAMHAUS.ORG", "//td[@class='chart-data-label col_left']/a[contains(@href, 'spamhaus.org')]/../following-sibling::td"),
        ("SBL.SPAMHAUS.ORG", "//td[@class='chart-data-label col_left']/a[contains(@href, 'spamhaus.org')]/../following-sibling::td"),
        ("ADDED TO THE BLOCK LIST", "//td[text()='Added to the Block List']/following-sibling::td"),
    ];

    for (key, xpath) in sections {
        if let Some(text) = get_element_text(driver, xpath).await? {
            data.insert(key.to_string(), text);
        }
    }

    Ok(data)
}

// Function to get IP information from ipinfo.io
async fn get_ip_info(ip: &str) -> Result<IpInfo, Error> {
    let url = format!("https://ipinfo.io/{}", ip);
    let response = reqwest::get(&url).await?;
    let ip_info: IpInfo = response.json().await?;
    Ok(ip_info)
}

// Main function to search Talos and display the results
async fn search_talos(query: &str) -> WebDriverResult<HashMap<String, HashMap<String, String>>> {
    let mut caps = DesiredCapabilities::chrome();
    //let profile_path = ""; // Update this to the path of your profile
    //caps.add_chrome_arg(&format!("--user-data-dir={}", profile_path))?;
    caps.add_chrome_arg("--homepage=about:blank")?;
    caps.add_chrome_arg("--no-sandbox")?;
    caps.add_chrome_arg("--disable-dev-shm-usage")?;

    let driver = WebDriver::new("http://localhost:57077", caps).await?;
    let url = format!("https://talosintelligence.com/reputation_center/lookup?search={}", query);
    driver.get(&url).await?;

    // Added delay to allow the webpage to load
    pause_with_delay(5);

    let mut data = HashMap::new();

    if let Some(location) = scrape_location_data(&driver).await? {
        data.insert("LOCATION DATA".to_string(), [("Location".to_string(), location)].iter().cloned().collect());
    }

    let owner_details = scrape_owner_details(&driver).await?;
    if !owner_details.is_empty() {
        data.insert("OWNER DETAILS".to_string(), owner_details);
    }

    let reputation_details = scrape_reputation_details(&driver).await?;
    if !reputation_details.is_empty() {
        data.insert("REPUTATION DETAILS".to_string(), reputation_details);
    }

    let email_volume_data = scrape_email_volume_data(&driver).await?;
    if !email_volume_data.is_empty() {
        data.insert("EMAIL VOLUME DATA".to_string(), email_volume_data);
    }

    let block_lists = scrape_block_lists(&driver).await?;
    if !block_lists.is_empty() {
        data.insert("BLOCK LISTS".to_string(), block_lists);
    }

    driver.quit().await?;
    Ok(data)
}

#[tokio::main]
async fn main() -> WebDriverResult<()> {
    env_logger::init();

    // Print ASCII art
    println!(" (\\(\\                              _____                        _     _____ _____                          ");
    println!("( -.-)                            / ____|                      | |   / ____/ ____|                         ");
    println!("o_(\")(\")                         | (___   __ _ _   _  ___  __ _| | _| (___| (___                           ");
    println!("            *                     \\___ \\ / _` | | | |/ _ \\/ _` | |/ /\\___ \\\\___ \\                          ");
    println!("                                  ____) | (_| | |_| |  __| (_| |   < ____) ____) |                         ");
    println!("            *                    |_____/ \\__, |\\__,_|\\___|\\__,______|_____|_____/        _     _____ _____ ");
    println!("                    *            |  _ \\     | |           | |/ ____|                    | |   / ____/ ____|");
    println!("                                 | |_) |_ __|___  __ _  __| | |     _ __ _   _ _ __ ___ | |__| (___| (___  ");
    println!("                    *            |  _ <| '__/ _ \\/ _` |/ _` | |    | '__| | | | '_ ` _ \\| '_ \\\\___ \\___ \\ ");
    println!("                            *    | |_) | | |  __| (_| | (_| | |____| |  | |_| | | | | | | |_) ____) ____) |");
    println!("                                 |____/|_|  \\___|\\__,_|\\__,_|\\_____|_|   \\__,_|_| |_| |_|_.__|_____|_____/ ");
    println!("                            *");
    println!("                                    *");
    println!("                                 _________");
    println!("                                (         )");
    println!("                                 |       |");
    println!("                                 |       |");
    println!("                                 (_______)");

    pause_with_delay(3);

    // Read the name of the most recently created file
    let latest_file_path = "latest_file.txt";
    let filename = if let Ok(file) = File::open(latest_file_path) {
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            line.trim().to_string()
        } else {
            eprintln!("Failed to read the latest file marker.");
            std::process::exit(1);
        }
    } else {
        eprintln!("Could not open the latest file marker.");
        std::process::exit(1);
    };

    // Read IP addresses from the file
    if let Ok(lines) = read_lines(&filename) {
        let mut results = HashMap::new();
        for line in lines {
            if let Ok(ip) = line {
                // Sanitize and process each IP address
                if let Some(sanitized_ip) = sanitize_input(&ip) {
                    println!("Processing IP: {}", sanitized_ip);

                    // Search Talos and display the results for each IP address
                    match search_talos(&sanitized_ip).await {
                        Ok(mut data) => {
                            if let Ok(ip_info) = get_ip_info(&sanitized_ip).await {
                                data.insert("IPINFO.IO DATA".to_string(), ip_info.to_hash_map());
                            }
                            results.insert(sanitized_ip.clone(), data);

                            if let Some(location_data) = results.get("LOCATION DATA") {
                                println!("\nLOCATION DATA");
                                if let Some(location) = location_data.get("Location") {
                                    println!("{:?}", location);
                                }
                            }

                            if let Some(owner_details) = results.get("OWNER DETAILS") {
                                println!("\nOWNER DETAILS");
                                for (key, value) in owner_details {
                                    println!("{}:\t{:?}", key, value);
                                }
                            }

                            if let Some(reputation_details) = results.get("REPUTATION DETAILS") {
                                println!("\nREPUTATION DETAILS");
                                for (key, value) in reputation_details {
                                    println!("{}:\t{:?}", key, value);
                                }
                            }

                            if let Some(email_volume_data) = results.get("EMAIL VOLUME DATA") {
                                println!("\nEMAIL VOLUME DATA");
                                for (key, value) in email_volume_data {
                                    println!("{}:\t{:?}", key, value);
                                }
                            }

                            if let Some(block_lists) = results.get("BLOCK LISTS") {
                                println!("\nBLOCK LISTS");
                                for (key, value) in block_lists {
                                    println!("{}:\t{:?}", key, value);
                                }
                            }

                            if let Some(talos_block_list) = results.get("TALOS SECURITY INTELLIGENCE BLOCK LIST") {
                                println!("\nTALOS SECURITY INTELLIGENCE BLOCK LIST");
                                for (key, value) in talos_block_list {
                                    println!("{}:\t{:?}", key, value);
                                }
                            }
                        }
                        Err(err) => eprintln!("Error during search: {}", err),
                    }
                }
            }
        }

        // Save the results to a new file
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let output_filename = format!("results_{}.txt", timestamp);
        let mut output_file = OpenOptions::new().create(true).write(true).open(output_filename.clone()).unwrap();
        for (ip, data) in results {
            writeln!(output_file, "IP: {}\nData: {:?}", ip, data).unwrap();
        }
        println!("Results saved to {}", output_filename);
    } else {
        eprintln!("Could not read IP addresses from the file.");
    }

    Ok(())
}

// A function to read lines from a file
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
