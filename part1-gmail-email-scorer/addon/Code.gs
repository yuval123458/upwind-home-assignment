const BACKEND_URL = 'https://enforced-uneven-sharpie.ngrok-free.dev';
const GMAIL_API_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';

function buildHomepageCard() {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            'Open an email and click "Analyze this email" to score it.'
          )
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Manage blocklist')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowBlocklist'))
        )
    )
    .build();
  return [card];
}

function buildScanCard(e) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText('Click below to scan the currently open email.')
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Analyze this email')
            .setOnClickAction(CardService.newAction().setFunctionName('onScanClicked'))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Manage blocklist')
            .setOnClickAction(CardService.newAction().setFunctionName('onShowBlocklist'))
        )
    )
    .build();
  return [card];
}

function onScanClicked(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const message = GmailApp.getMessageById(e.gmail.messageId);

    const payload = {
      message_id: e.gmail.messageId,
      subject: message.getSubject(),
      sender: message.getFrom(),
      reply_to: message.getReplyTo() || null,
      body_plain: message.getPlainBody(),
      body_html: message.getBody(),
      authentication_results: message.getHeader('Authentication-Results') || null,
    };

    const response = UrlFetchApp.fetch(BACKEND_URL + '/score', {
      method: 'post',
      contentType: 'application/json',
      headers: backendHeaders(),
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });

    const code = response.getResponseCode();
    const body = response.getContentText();

    if (code !== 200) {
      return CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification().setText('Backend ' + code + ': ' + body.substring(0, 140))
        )
        .build();
    }

    const result = JSON.parse(body);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildResultCard(result, payload.sender)))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Error: ' + err.message))
      .build();
  }
}

function buildResultCard(result, sender) {
  const builder = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle('Score: ' + result.score + ' / 100')
      .setSubtitle(result.band.toUpperCase())
  );

  const signalsSection = CardService.newCardSection().setHeader('Signals');
  result.signals.forEach(function (s) {
    signalsSection.addWidget(
      CardService.newKeyValue()
        .setTopLabel(s.name + ' (+' + s.points + ')')
        .setContent(s.evidence)
        .setMultiline(true)
    );
  });
  builder.addSection(signalsSection);

  builder.addSection(
    CardService.newCardSection()
      .setHeader('Explanation')
      .addWidget(CardService.newTextParagraph().setText(result.explanation))
  );

  builder.addSection(
    CardService.newCardSection()
      .setHeader('Recommendation')
      .addWidget(CardService.newTextParagraph().setText(result.recommendation))
  );

  if (sender) {
    builder.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextButton()
          .setText('Block sender')
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName('onBlockClicked')
              .setParameters({ sender: sender })
          )
      )
    );
  }

  return builder.build();
}

function onBlockClicked(e) {
  try {
    const raw = e.parameters.sender;
    const match = /[\w.+-]+@[\w-]+\.[\w.-]+/.exec(raw);
    const email = match ? match[0].toLowerCase() : raw.toLowerCase();

    const filterId = gmailCreateFilter(email);
    backendAddBlocklist(email, filterId);

    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText(
          'Blocked ' + email + '. Future emails go to Trash.'
        )
      )
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Block failed: ' + err.message))
      .build();
  }
}

function onShowBlocklist(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildBlocklistCard()))
    .build();
}

function buildBlocklistCard() {
  let entries;
  try {
    entries = backendListBlocklist();
  } catch (err) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Blocklist'))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText('Error loading blocklist: ' + err.message)
        )
      )
      .build();
  }

  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle('Blocklist').setSubtitle(entries.length + ' entries')
  );

  if (entries.length === 0) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'No blocked senders yet. Block one from a scan result.'
        )
      )
    );
  } else {
    const section = CardService.newCardSection();
    entries.forEach(function (entry) {
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel(entry.value)
          .setContent(entry.gmail_filter_id ? 'Filter active in Gmail' : 'No filter (backend only)')
          .setButton(
            CardService.newTextButton()
              .setText('Unblock')
              .setOnClickAction(
                CardService.newAction()
                  .setFunctionName('onUnblockClicked')
                  .setParameters({
                    entryId: String(entry.id),
                    filterId: entry.gmail_filter_id || '',
                  })
              )
          )
      );
    });
    card.addSection(section);
  }
  return card.build();
}

function onUnblockClicked(e) {
  try {
    const entryId = parseInt(e.parameters.entryId, 10);
    const filterId = e.parameters.filterId;

    if (filterId) {
      gmailDeleteFilter(filterId);
    }
    backendRemoveBlocklist(entryId);

    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Unblocked.'))
      .setNavigation(CardService.newNavigation().updateCard(buildBlocklistCard()))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Unblock failed: ' + err.message))
      .build();
  }
}

function backendHeaders() {
  return {
    Authorization: 'Bearer ' + ScriptApp.getIdentityToken(),
    'ngrok-skip-browser-warning': 'true',
  };
}

function gmailHeaders() {
  return { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() };
}

function gmailCreateFilter(senderEmail) {
  const body = {
    criteria: { from: senderEmail },
    action: { addLabelIds: ['TRASH'] },
  };
  const response = UrlFetchApp.fetch(GMAIL_API_BASE + '/settings/filters', {
    method: 'post',
    contentType: 'application/json',
    headers: gmailHeaders(),
    payload: JSON.stringify(body),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() !== 200) {
    throw new Error('Gmail create filter failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText()).id;
}

function gmailDeleteFilter(filterId) {
  const response = UrlFetchApp.fetch(
    GMAIL_API_BASE + '/settings/filters/' + filterId,
    { method: 'delete', headers: gmailHeaders(), muteHttpExceptions: true }
  );
  const code = response.getResponseCode();
  if (code !== 204 && code !== 404) {
    throw new Error('Gmail delete filter failed: ' + code + ' ' + response.getContentText());
  }
}

function backendAddBlocklist(senderEmail, filterId) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist', {
    method: 'post',
    contentType: 'application/json',
    headers: backendHeaders(),
    payload: JSON.stringify({ value: senderEmail, gmail_filter_id: filterId }),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend add failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendListBlocklist() {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist', {
    method: 'get',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  if (response.getResponseCode() >= 300) {
    throw new Error('Backend list failed: ' + response.getContentText());
  }
  return JSON.parse(response.getContentText());
}

function backendRemoveBlocklist(entryId) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/blocklist/' + entryId, {
    method: 'delete',
    headers: backendHeaders(),
    muteHttpExceptions: true,
  });
  const code = response.getResponseCode();
  if (code >= 300 && code !== 404) {
    throw new Error('Backend remove failed: ' + response.getContentText());
  }
}
