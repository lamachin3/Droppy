import { SlidingTab } from "@/components";
import { FileDetailsStrings } from "./file-details-strings";
import { FileDetailsYara } from "./file-details-yara";
import { FileDetailsVirustotal } from "./file-details-virustotal";

export function FileDetailsTabs({activeTab, handleTabChange, file}: FileDetailsTabsProps) {
    const tabs = [
        { id: "strings", icon: "solar:code-file-linear", label: "Strings", badge: file.strings_results?.some((str: any) => str.caution_level === "high") ? true : false, content:
            <FileDetailsStrings file={file} />
         },
        { id: "yara", icon: "file-icons:yara", label: "Yara Results", badge: file.yara_results?.some((yara: any) => yara.meta.severity > 40) ? true : false, content: 
            <FileDetailsYara file={file} />
         },
        { id: "virustotal", icon: "simple-icons:virustotal", label: "Virustotal", badge: file.virustotal_results?.found ? true : false, content:
            <FileDetailsVirustotal file={file} />
        },
        { id: "edr", icon: "fa6-solid:shield-virus", label: "EDR Plugins", content: null, disabled: true },
    ];

    return (
        <SlidingTab
            tabs={tabs}
            defaultTab={activeTab}
            onChange={handleTabChange}
        />
    )
}

interface FileDetailsTabsProps {
    activeTab: string;
    handleTabChange: (tabId: string) => void;
    file: any;
}
