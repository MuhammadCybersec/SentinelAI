"""
===========================================================
Project : Sentinel AI
Module  : Interactive CLI
File ID : CLI-001
Version : 0.1.0
===========================================================
"""

from app.core.logger import sentinel_logger


class CLI:
    def __init__(self, manager):

        self.manager = manager

    def start(self):

        sentinel_logger.info("CLI Started")

        print("\n")
        print("=" * 60)
        print(" Sentinel AI Interactive Console ")
        print(" Type 'exit' to quit.")
        print("=" * 60)

        while True:
            command = input("\nSentinelAI> ").strip()

            if command.lower() == "exit":
                print("Goodbye!")
                break

            if command == "":
                continue

            try:
                result = self.manager.handle(command)

                # ============================================
                # Project Object
                # ============================================

                if hasattr(result, "id"):
                    if command.lower().startswith("create"):
                        print("\nProject Created Successfully")

                    elif command.lower() == "current project":
                        print("\nCurrent Project")

                    else:
                        print("\nProject Information")

                    print("-" * 40)
                    print(f"ID          : {result.id}")
                    print(f"Name        : {result.name}")
                    print(f"Target      : {result.target}")
                    print(f"Description : {result.description}")

                # ============================================
                # List of Projects
                # ============================================

                elif isinstance(result, list):
                    print("\nProjects")
                    print("-" * 60)

                    if not result:
                        print("No projects found.")

                    else:
                        for project in result:
                            print(f"ID          : {project.id}")
                            print(f"Name        : {project.name}")
                            print(f"Target      : {project.target}")
                            print(f"Description : {project.description}")
                            print("-" * 60)

                # ============================================
                # Recon Report
                # ============================================

                elif isinstance(result, dict):
                    print("\nRecon Report")
                    print("-" * 40)
                    if "commands" in result:
                        print("\nAvailable Commands")
                        print("-" * 40)

                        for cmd in result["commands"]:
                            print(f"  - {cmd}")

                        continue
                    for key, value in result.items():
                        # Skip raw headers
                        if key == "headers":
                            continue

                        if key == "dns_records":
                            print("\nDNS Records")
                            print("-" * 40)

                            for record_type, records in value.items():
                                print(f"\n{record_type}")
                                if records:
                                    for record in records:
                                        print(f"  - {record}")

                                else:
                                    print("  No records found.")
                            continue

                        if key == "waf":
                            print("\nWAF Detection")
                            print("-" * 40)
                            print(f"Provider : {value['provider']}")
                            print(f"Enabled  : {value['enabled']}")
                            continue

                        if key == "http_methods":
                            print("\nHTTP Methods")
                            print("-" * 40)
                            if value:
                                for method in value:
                                    print(f"  - {method}")
                            else:
                                print("No methods detected.")
                            continue

                        if key == "javascript_files":
                            print("\nJavaScript Files")
                            print("-" * 40)
                            if value:
                                for js_file in value:
                                    print(js_file)
                            else:
                                print("No JavaScript files found.")
                            continue

                        if key == "javascript_endpoints":
                            print("\nJavaScript Endpoints")
                            print("-" * 40)
                            if value:
                                for endpoint in value:
                                    print(endpoint)
                            else:
                                print("No JavaScript endpoints found.")
                            continue

                        if key == "javascript_secrets":
                            print("\nJavaScript Secrets")
                            print("-" * 40)
                            if value:
                                for secret in value:
                                    print(f"[{secret['type']}]")
                                    print(f"Value  : {secret['value']}")
                                    print(f"Source : {secret['source']}")
                                    print()

                                print("No secrets found.")
                                continue

                            else:
                                print("No JavaScript secrets found.")
                            continue

                        if key == "api_discovery":
                            print("\nAPI Discovery")
                            print("-" * 40)
                            if value:
                                for api in value:
                                    print(f"{api['status']}  {api['path']}")
                                    print(f"      {api['url']}")

                            else:
                                print("No API endpoints found.")
                            continue

                        # Print Security Headers
                        if key == "security_headers":
                            print("\nSecurity Headers")
                            print("-" * 40)

                            if isinstance(value, dict):
                                for h, v in value.items():
                                    print(f"{h:30}: {v}")

                            continue

                        # Print Open Ports
                        if key == "open_ports":
                            print("\nOpen Ports")
                            print("-" * 40)
                            if value:
                                for port in value:
                                    print(f"Port {port} is open.")

                            else:
                                print("No common ports found.")
                            continue

                        if key == "subdomains":
                            print("\nSubdomains")
                            print("-" * 40)
                            if value:
                                for subdomain in value:
                                    print(subdomain)
                            else:
                                print("No subdomains found.")
                            continue

                        if key == "sensitive_files":
                            print("\nSensitive Files")
                            print("-" * 40)
                            if value:
                                for item in value:
                                    print(f"{item['file']:30} {item['status']}")
                            else:
                                print("No sensitive files found.")
                            continue

                        # Print Technologies
                        if key == "technologies":
                            techs = ", ".join(value) if value else "Unknown"
                            print(f"Technologies : {techs}")

                            continue

                        # Print remaining values
                        print(f"{key.capitalize():12}: {value}")

                # ============================================
                # Normal Text Response
                # ============================================

                else:
                    print(result)

            except Exception as e:
                print(f"Error: {e}")
