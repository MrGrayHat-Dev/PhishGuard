  const inp = document.getElementById('backend');
    chrome.storage.local.get(['backendUrl'], (d) => { inp.value = d.backendUrl || 'http://localhost:8080/scan'; });
    document.getElementById('save').addEventListener('click', () => {
      chrome.storage.local.set({ backendUrl: inp.value }, () => alert('Saved'));
    });