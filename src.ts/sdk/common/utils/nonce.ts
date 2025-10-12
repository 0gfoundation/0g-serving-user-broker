export function getNonce(): number {
    const now = new Date()
    return now.getTime() * 10000 + 40
}
