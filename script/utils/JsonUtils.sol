// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Vm.sol";

library JsonUtils {
    /// @dev Write a key-value pair to a JSON file, handling existing entries
    /// @param vm The VM to run the commands with
    /// @param filePath The path to the JSON file
    /// @param key The key to write
    /// @param value The value to write
    function writeJsonEntry(Vm vm, string memory filePath, string memory key, string memory value) internal {
        // Read existing file if it exists
        string memory jsonContent = "";
        try vm.readFile(filePath) returns (string memory content) {
            jsonContent = content;
        } catch {
            // File doesn't exist yet, start with empty object
            jsonContent = "{}";
        }

        // Parse existing entries into a map
        string[] memory entries = parseJsonEntries(jsonContent);

        // Create new entries array with updated/added entry
        string[] memory newEntries = new string[](entries.length + 1);
        bool found = false;

        // Copy existing entries, replacing if key matches
        for (uint256 i = 0; i < entries.length; i++) {
            string memory entry = entries[i];
            if (bytes(entry).length == 0) continue;

            string memory currentKey = extractKey(entry);
            if (keccak256(bytes(currentKey)) == keccak256(bytes(key))) {
                newEntries[i] = string(abi.encodePacked('"', key, '":"', value, '"'));
                found = true;
            } else {
                newEntries[i] = entry;
            }
        }

        // Add new entry if not found
        if (!found) {
            newEntries[entries.length] = string(abi.encodePacked('"', key, '":"', value, '"'));
        }

        // Construct new JSON
        string memory newJson = "{";
        for (uint256 i = 0; i < newEntries.length; i++) {
            if (bytes(newEntries[i]).length == 0) continue;
            if (i > 0 && bytes(newEntries[i - 1]).length > 0) {
                newJson = string(abi.encodePacked(newJson, ","));
            }
            newJson = string(abi.encodePacked(newJson, newEntries[i]));
        }
        newJson = string(abi.encodePacked(newJson, "}"));

        // Write back to file
        vm.writeFile(filePath, newJson);
    }

    /// @dev Parse JSON string into array of key-value entries
    function parseJsonEntries(string memory json) internal pure returns (string[] memory) {
        // Remove whitespace and outer braces
        string memory cleaned = cleanJson(json);
        if (bytes(cleaned).length <= 2) return new string[](0);

        // Split by commas
        string[] memory entries = splitByComma(substring(cleaned, 1, bytes(cleaned).length - 1));
        return entries;
    }

    /// @dev Extract key from a JSON entry
    function extractKey(string memory entry) internal pure returns (string memory) {
        uint256 colonPos = findChar(entry, ":");
        if (colonPos == 0) return "";

        string memory key = substring(entry, 0, colonPos);
        // Remove quotes
        if (bytes(key).length >= 2 && bytes(key)[0] == '"' && bytes(key)[bytes(key).length - 1] == '"') {
            return substring(key, 1, bytes(key).length - 1);
        }
        return key;
    }

    /// @dev Split string by commas, respecting quotes
    function splitByComma(string memory str) internal pure returns (string[] memory) {
        bytes memory strBytes = bytes(str);
        bool inQuotes = false;
        uint256 count = 1;

        // Count number of top-level commas
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == '"') {
                inQuotes = !inQuotes;
            } else if (strBytes[i] == "," && !inQuotes) {
                count++;
            }
        }

        // Create array and split
        string[] memory parts = new string[](count);
        uint256 partIndex = 0;
        uint256 lastIndex = 0;
        inQuotes = false;

        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == '"') {
                inQuotes = !inQuotes;
            } else if (strBytes[i] == "," && !inQuotes) {
                parts[partIndex] = substring(str, lastIndex, i);
                lastIndex = i + 1;
                partIndex++;
            }
        }

        // Add last part
        if (lastIndex < strBytes.length) {
            parts[partIndex] = substring(str, lastIndex, strBytes.length);
        }

        return parts;
    }

    /// @dev Clean up a JSON string by removing whitespace
    function cleanJson(string memory json) internal pure returns (string memory) {
        bytes memory jsonBytes = bytes(json);
        bytes memory cleaned = new bytes(jsonBytes.length);
        uint256 cleanedLength = 0;
        bool inQuotes = false;

        for (uint256 i = 0; i < jsonBytes.length; i++) {
            bytes1 char = jsonBytes[i];

            if (char == '"') {
                inQuotes = !inQuotes;
            }

            if (inQuotes || (char != " " && char != "\n" && char != "\r" && char != "\t")) {
                cleaned[cleanedLength] = char;
                cleanedLength++;
            }
        }

        bytes memory result = new bytes(cleanedLength);
        for (uint256 i = 0; i < cleanedLength; i++) {
            result[i] = cleaned[i];
        }

        return string(result);
    }

    /// @dev Helper function to find a character in a string
    function findChar(string memory str, bytes1 char) internal pure returns (uint256) {
        bytes memory strBytes = bytes(str);
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == char) {
                return i;
            }
        }
        return 0;
    }

    /// @dev Helper function to get a substring
    function substring(string memory str, uint256 startIndex, uint256 endIndex) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            result[i - startIndex] = strBytes[i];
        }
        return string(result);
    }
}
